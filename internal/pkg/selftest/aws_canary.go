package selftest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// AWSCanary holds the disposable AWS resources created for one self-test run.
type AWSCanary struct {
	DNSZone      string // e.g. "ab12cd34ef56.net"
	BucketName   string // e.g. "subdomain.ab12cd34ef56.net"
	HostedZoneID string // populated after the hosted zone is created
}

// Matches reports whether a scan result item refers to this canary. Scan items
// are formatted as "name -> resourceDNSName"; both halves contain the canary's
// unique random DNS zone, so a substring check is sufficient.
func (c AWSCanary) Matches(item string) bool {
	return strings.Contains(item, c.DNSZone)
}

// Split separates the real dangling records from the canary among the scan
// results.
func (c AWSCanary) Split(items []string) (real []string, found bool) {
	for _, item := range items {
		if c.Matches(item) {
			found = true
			continue
		}
		real = append(real, item)
	}
	return real, found
}

// generateAWSNames returns a random DNS zone and the bucket name derived from it.
func generateAWSNames() (dnsZone string, bucketName string, err error) {
	hexStr, err := randomHex(6)
	if err != nil {
		return "", "", err
	}
	dnsZone = hexStr + ".net"
	bucketName = "subdomain." + dnsZone
	return dnsZone, bucketName, nil
}

// SetupDanglingCNAME creates a hosted zone, an S3 bucket and a CNAME pointing
// to the bucket, then deletes the bucket so the record becomes dangling.
func SetupDanglingCNAME(ctx context.Context, r53Client *route53.Client, s3Client *s3.Client, region string) (AWSCanary, error) {
	dnsZone, bucketName, err := generateAWSNames()
	if err != nil {
		return AWSCanary{}, err
	}
	canary := AWSCanary{DNSZone: dnsZone, BucketName: bucketName}

	callerRef, err := randomHex(6)
	if err != nil {
		return canary, err
	}

	zoneResp, err := r53Client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		Name:            aws.String(canary.DNSZone),
		CallerReference: aws.String(callerRef),
	})
	if err != nil {
		return canary, fmt.Errorf("setupDanglingCNAME: create hosted zone failed: %w", err)
	}
	canary.HostedZoneID = *zoneResp.HostedZone.Id

	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(canary.BucketName),
		CreateBucketConfiguration: &s3Types.CreateBucketConfiguration{
			LocationConstraint: s3Types.BucketLocationConstraint(region),
		},
	})
	if err != nil {
		return canary, fmt.Errorf("setupDanglingCNAME: create bucket failed: %w", err)
	}

	bucketFQDN := fmt.Sprintf("%s.s3.%s.amazonaws.com", canary.BucketName, region)
	_, err = r53Client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(canary.HostedZoneID),
		ChangeBatch: &route53Types.ChangeBatch{
			Changes: []route53Types.Change{
				{
					Action: route53Types.ChangeActionCreate,
					ResourceRecordSet: &route53Types.ResourceRecordSet{
						Name: aws.String(canary.BucketName),
						Type: route53Types.RRTypeCname,
						TTL:  aws.Int64(300),
						ResourceRecords: []route53Types.ResourceRecord{
							{Value: aws.String(bucketFQDN)},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return canary, fmt.Errorf("setupDanglingCNAME: create CNAME record failed: %w", err)
	}

	// Delete the bucket so the CNAME is left dangling.
	if err = deleteBucket(ctx, s3Client, canary.BucketName); err != nil {
		return canary, fmt.Errorf("setupDanglingCNAME: delete bucket failed: %w", err)
	}

	return canary, nil
}

// Teardown removes every resource created for the canary. It returns the first
// error encountered so the caller can decide how to handle a failed cleanup.
func (c AWSCanary) Teardown(ctx context.Context, r53Client *route53.Client, s3Client *s3.Client) error {
	if c.HostedZoneID != "" {
		records, err := r53Client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(c.HostedZoneID),
		})
		if err != nil {
			return fmt.Errorf("teardown: list resource record sets failed: %w", err)
		}

		var changes []route53Types.Change
		for _, rec := range records.ResourceRecordSets {
			// Route53 rejects deleting a hosted zone until only its auto-managed NS
			// and SOA records remain, so delete every other record and keep those.
			if rec.Type != route53Types.RRTypeNs && rec.Type != route53Types.RRTypeSoa {
				recCopy := rec
				changes = append(changes, route53Types.Change{
					Action:            route53Types.ChangeActionDelete,
					ResourceRecordSet: &recCopy,
				})
			}
		}
		if len(changes) > 0 {
			_, err = r53Client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
				HostedZoneId: aws.String(c.HostedZoneID),
				ChangeBatch:  &route53Types.ChangeBatch{Changes: changes},
			})
			if err != nil {
				return fmt.Errorf("teardown: change resource record sets failed: %w", err)
			}
		}

		_, err = r53Client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{
			Id: aws.String(c.HostedZoneID),
		})
		if err != nil {
			return fmt.Errorf("teardown: delete hosted zone failed: %w", err)
		}
	}

	// The bucket is intentionally deleted during setup to create the dangling
	// state, so a NoSuchBucket error here is expected on the happy path.
	err := deleteBucket(ctx, s3Client, c.BucketName)
	if err != nil && !isNoSuchBucket(err) {
		return fmt.Errorf("teardown: delete bucket failed: %w", err)
	}

	return nil
}

func deleteBucket(ctx context.Context, s3Client *s3.Client, bucketName string) error {
	emptyBucket(ctx, s3Client, bucketName)
	_, err := s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	return err
}

// isNoSuchBucket reports whether err is an S3 "NoSuchBucket" API error. S3 does
// not reliably return the typed *s3Types.NoSuchBucket, so match on the error code.
func isNoSuchBucket(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucket"
}

func emptyBucket(ctx context.Context, s3Client *s3.Client, bucketName string) {
	paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isNoSuchBucket(err) {
				return
			}
			slog.Error("emptyBucket: list objects failed", "Error", err.Error())
			return
		}
		if len(page.Contents) == 0 {
			break
		}
		var ids []s3Types.ObjectIdentifier
		for _, obj := range page.Contents {
			ids = append(ids, s3Types.ObjectIdentifier{Key: obj.Key})
		}
		_, err = s3Client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &s3Types.Delete{Objects: ids},
		})
		if err != nil {
			slog.Error("emptyBucket: delete objects failed", "Error", err.Error())
			return
		}
	}
}
