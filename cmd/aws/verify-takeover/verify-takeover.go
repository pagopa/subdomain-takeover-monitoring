package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"subdomain/internal/pkg/logger"
	"subdomain/internal/pkg/slack"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebsTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	REGION                             = "eu-south-1"
	S3_RESEARCH_PATTERN                = ".s3."
	ELASTIC_BEANSTALK_RESEARCH_PATTERN = ".elasticbeanstalk."
	AWS_ORG                            = "aws"
)

var VULNERABLE_AWS_RESOURCES []string = []string{"S3", "Elasticbeanstalk"}

type ExtractedResult struct {
	Name            string //images.example.com or test23
	ResourceDNSName string //images.example.com.s3.us-east-1.amazonaws.com or test23.eu-south-1.elasticbeanstalk.com
	Found           bool
	HostedZoneName  string
	HostedZoneId    string
	Type            string //S3, Elasticbeanstalk
}

func HandleRequest(ctx context.Context, event events.SQSEvent) (string, error) {
	if err := runUnhappyPathCheck(ctx); err != nil {
		slog.Error("Unhappy path check failed", "Error", err.Error())
		if notifyErr := slack.SendSlackNotification(os.Getenv("CHANNEL_ID_DEBUG"), fmt.Sprintf("Self-test ERROR in %s: %s", AWS_ORG, err.Error())); notifyErr != nil {
			slog.Error("Failed to send Slack message", "Error", notifyErr.Error())
		}
	}

	var vulnerableItemsOrg []string
	var err error
	for _, record := range event.Records {
		vulnerableItemsOrg, err = processMessage(record)
		if err != nil {
			return "", err
		}
	}
	slog.Info("Subdomain takeover monitoring tool has correctly verified all AWS accounts belonging to organization.")

	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")
	if len(vulnerableItemsOrg) > 0 {
		var formattedResources []string
		for _, resource := range vulnerableItemsOrg {
			formattedResources = append(formattedResources, "• "+resource)
		}
		resourceListText := strings.Join(formattedResources, "\n")
		message := fmt.Sprintf("Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover.\nThe pointed resources do not seem to belong to the organization. Please remove any dangling DNS records from the hosted zones to mitigate the risk.\n", AWS_ORG)
		err = slack.SendSlackNotification(slackChannelID, message, resourceListText)
	} else {
		message := fmt.Sprintf("All DNS records in %s are secure and properly configured.", AWS_ORG)
		err = slack.SendSlackNotification(slackChannelIDDebug, message)
	}
	if err != nil {
		return "", fmt.Errorf("slack notification failed %v ", err)
	}

	slog.Debug("Subdomain takeover monitoring tool sent the result of execution via Slack.")

	return "Execution completed successfully", nil
}

func main() {
	logger.SetLogger()
	slog.Debug("Starting Lambda...")
	lambda.Start(HandleRequest)
}

func processMessage(record events.SQSMessage) ([]string, error) {
	accounts := new([]types.Account)
	err := json.Unmarshal([]byte(record.Body), accounts)
	if err != nil {
		return nil, err
	}
	var vulnerableItemsOrg []string
	for _, account := range *accounts {
		vulnerableItemAccount, accountDNSRecord, err := processAccount(&account)
		if err != nil {
			// It does not return because the tool continue with other accounts.
			slog.Error("Error in processing the account....", "Error", err.Error())
		}
		vulnerableItemsOrg = append(vulnerableItemsOrg, vulnerableItemAccount...)
		slog.Info("Listing DNS Record for each account...", "Account: ", account.Name, "DNS Records: ", accountDNSRecord)
	}
	return vulnerableItemsOrg, nil
}

func processAccount(account *types.Account) ([]string, map[string]*route53.ListResourceRecordSetsOutput, error) {
	// Create clients for r53, s3, ebs queries
	r53Client, s3Client, ebsClient, err := createClients(account.Id)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Clients created")
	DNSZonesPoitingToAWSResource := make(map[string]*ExtractedResult)
	AWSResources := make(map[string]bool)

	// List potential vulnerable CNAME record belonging to the account read from the queue
	accountDNSRecord, err := listPotentialVulnerableDNSRecord(r53Client, DNSZonesPoitingToAWSResource)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Listed potential vulnerable CNAME record")

	// List S3 buckets belonging to the assumed account
	err = listS3Buckets(s3Client, AWSResources)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Listed account's S3")
	// List EBS environments belonging to the assumed account
	err = listEBSEnvironment(ebsClient, AWSResources)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug(fmt.Sprintf("Resources vulnerable to subdomain takeover for account %s - %s:\n", *account.Name, *account.Id))
	slog.Debug("Listed account's EBS")

	// Verify takeover
	vulnerableAWSResources, vulnerableItems := verifyTakeover(DNSZonesPoitingToAWSResource, AWSResources)

	if len(vulnerableAWSResources) > 0 {
		jsonResult, _ := json.Marshal(vulnerableAWSResources)
		*account.Name = strings.ReplaceAll(strings.ReplaceAll(*account.Name, "\n", ""), "\r", "")
		*account.Id = strings.ReplaceAll(strings.ReplaceAll(*account.Id, "\n", ""), "\r", "")

		slog.Debug(string(jsonResult))
	}

	return vulnerableItems, accountDNSRecord, nil
}

func createClients(accountID *string) (*route53.Client, *s3.Client, *elasticbeanstalk.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, nil, nil, err
	}
	roleArnOsEnv := os.Getenv("PRODSEC_READONLY_ROLE")
	roleArn := fmt.Sprintf(roleArnOsEnv, *accountID)
	stsClient := *sts.NewFromConfig(cfg)
	roleSessionName := os.Getenv("LIST_ACCOUNTS_ROLE_SESSION_NAME")
	assumeRoleOutput, err := stsClient.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(900)})
	if err != nil {
		return nil, nil, nil, err
	}
	r53Client := route53.NewFromConfig(cfg, func(o *route53.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			*assumeRoleOutput.Credentials.AccessKeyId,
			*assumeRoleOutput.Credentials.SecretAccessKey,
			*assumeRoleOutput.Credentials.SessionToken,
		)
	})
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			*assumeRoleOutput.Credentials.AccessKeyId,
			*assumeRoleOutput.Credentials.SecretAccessKey,
			*assumeRoleOutput.Credentials.SessionToken,
		)
	})
	ebsClient := elasticbeanstalk.NewFromConfig(cfg, func(o *elasticbeanstalk.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			*assumeRoleOutput.Credentials.AccessKeyId,
			*assumeRoleOutput.Credentials.SecretAccessKey,
			*assumeRoleOutput.Credentials.SessionToken,
		)
	})

	return r53Client, s3Client, ebsClient, nil
}

func listPotentialVulnerableDNSRecord(r53Client *route53.Client, DNSZonesPoitingToAWSResource map[string]*ExtractedResult) (map[string]*route53.ListResourceRecordSetsOutput, error) {
	// Pagination ok
	pagination := true
	var nextMarker *string
	var resultDNS []route53Types.HostedZone
	mapDNSZones := make(map[string]*route53.ListResourceRecordSetsOutput)
	for pagination {
		tempRes, err := r53Client.ListHostedZones(context.TODO(), &route53.ListHostedZonesInput{Marker: nextMarker})
		if err != nil {
			return nil, err
		}
		pagination = tempRes.IsTruncated
		nextMarker = tempRes.NextMarker
		resultDNS = append(resultDNS, tempRes.HostedZones...)
	}
	// Pagination
	for _, hostedZone := range resultDNS {
		pagination = true
		nextMarker = nil
		for pagination {
			tmpExtractedResultAWSResources := make(map[string]*ExtractedResult)
			recordSests, err := r53Client.ListResourceRecordSets(context.TODO(), &route53.ListResourceRecordSetsInput{
				HostedZoneId:          hostedZone.Id,
				StartRecordIdentifier: nextMarker,
			})
			if err != nil {
				return nil, err
			}
			mapDNSZones[*hostedZone.Name] = recordSests
			pagination = recordSests.IsTruncated
			nextMarker = recordSests.NextRecordIdentifier
			tmpExtractedResultAWSResources = extractCNAMERecords(recordSests, hostedZone)
			maps.Copy(DNSZonesPoitingToAWSResource, tmpExtractedResultAWSResources)
		}
	}
	return mapDNSZones, nil
}

func extractHostname(value string) string {
	// Handle both "scheme://host" and plain "host" formats.
	if idx := strings.Index(value, "://"); idx != -1 {
		value = value[idx+3:]
	}
	// Strip any trailing path or dot.
	if idx := strings.Index(value, "/"); idx != -1 {
		value = value[:idx]
	}
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(value)), ".")
}

func checkPresenceAwsResource(record *route53Types.ResourceRecordSet, hostedZone route53Types.HostedZone, AWSResourceOutput map[string]*ExtractedResult) {
	rawValue := *record.ResourceRecords[0].Value
	hostname := extractHostname(rawValue)

	tmpExtractedResult := &ExtractedResult{
		ResourceDNSName: hostname,
		Found:           true,
		Name:            strings.ToLower(strings.TrimRight(strings.TrimSpace(*record.Name), ".")),
		HostedZoneName:  *hostedZone.Name,
		HostedZoneId:    *hostedZone.Id,
	}
	if strings.Contains(rawValue, S3_RESEARCH_PATTERN) {
		tmpExtractedResult.Type = VULNERABLE_AWS_RESOURCES[0] //S3
		AWSResourceOutput[tmpExtractedResult.Name] = tmpExtractedResult
	} else if strings.Contains(rawValue, ELASTIC_BEANSTALK_RESEARCH_PATTERN) {
		tmpExtractedResult.Type = VULNERABLE_AWS_RESOURCES[1] //Elasticbeanstalk
		AWSResourceOutput[tmpExtractedResult.ResourceDNSName] = tmpExtractedResult
	}
}

func extractCNAMERecords(recordSetsOutput *route53.ListResourceRecordSetsOutput, hostedZone route53Types.HostedZone) map[string]*ExtractedResult {
	possibleDanglingRecord := make(map[string]*ExtractedResult)
	for _, record := range recordSetsOutput.ResourceRecordSets {
		// Check only CNAME records
		if record.Type == route53Types.RRTypeCname {
			// Check whether DNS record point to a S3 bucket o EBS env
			if strings.Contains(*record.ResourceRecords[0].Value, S3_RESEARCH_PATTERN) || strings.Contains(*record.ResourceRecords[0].Value, ELASTIC_BEANSTALK_RESEARCH_PATTERN) {
				checkPresenceAwsResource(&record, hostedZone, possibleDanglingRecord)
			}
		}
	}
	return possibleDanglingRecord
}

func listS3Buckets(s3Client *s3.Client, AWSResources map[string]bool) error {
	// Pagination
	p := s3.NewListBucketsPaginator(s3Client, &s3.ListBucketsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			return err
		}
		for _, bucket := range page.Buckets {
			AWSResources[strings.ToLower(*bucket.Name)] = true
		}
	}
	return nil
}

func listEBSEnvironment(ebsClient *elasticbeanstalk.Client, AWSResources map[string]bool) error {
	// Pagination
	pagination := true
	var nextMarker *string
	var environments []ebsTypes.EnvironmentDescription
	for pagination {
		tempEnv, err := ebsClient.DescribeEnvironments(context.TODO(), &elasticbeanstalk.DescribeEnvironmentsInput{NextToken: nextMarker})
		if err != nil {
			return err
		}
		environments = append(environments, tempEnv.Environments...)
		if tempEnv.NextToken == nil {
			pagination = false
			nextMarker = tempEnv.NextToken
		}
	}
	for _, environment := range environments {
		if environment.CNAME != nil && environment.Status != ebsTypes.EnvironmentStatusTerminated {
			AWSResources[strings.ToLower(*environment.CNAME)] = true
		}
	}
	return nil
}

func verifyTakeover(DNSZonesPoitingToAWSResource map[string]*ExtractedResult, AWSResources map[string]bool) ([]*ExtractedResult, []string) {
	var subdomainTakeover []*ExtractedResult
	var vulnerableItems []string
	for key, value := range DNSZonesPoitingToAWSResource {
		_, found := AWSResources[key]
		if !found {
			subdomainTakeover = append(subdomainTakeover, value)
			vulnerableItems = append(vulnerableItems, value.Name+" -> "+value.ResourceDNSName)
		}
	}
	return subdomainTakeover, vulnerableItems
}

func generateTestNames() (dnsZone string, bucketName string, err error) {
	b := make([]byte, 6)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	hexStr := hex.EncodeToString(b)
	dnsZone = hexStr + ".net"
	bucketName = "subdomain." + dnsZone
	return dnsZone, bucketName, nil
}

func emptyBucket(ctx context.Context, s3Client *s3.Client, bucketName string) {
	paginator := s3.NewListObjectsV2Paginator(s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			var nsb *s3Types.NoSuchBucket
			if errors.As(err, &nsb) {
				return
			}
			slog.Error("emptyBucket: failed to list objects", "Error", err.Error())
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
			slog.Error("emptyBucket: failed to delete objects", "Error", err.Error())
			return
		}
	}
}

func setupDanglingCNAME(ctx context.Context, r53Client *route53.Client, s3Client *s3.Client, dnsZone string, bucketName string) (string, error) {
	callerRefBytes := make([]byte, 6)
	if _, err := rand.Read(callerRefBytes); err != nil {
		return "", err
	}
	callerRef := hex.EncodeToString(callerRefBytes)

	zoneResp, err := r53Client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		Name:            aws.String(dnsZone),
		CallerReference: aws.String(callerRef),
	})
	if err != nil {
		return "", fmt.Errorf("setupDanglingCNAME: CreateHostedZone failed: %w", err)
	}
	hostedZoneId := *zoneResp.HostedZone.Id

	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
		CreateBucketConfiguration: &s3Types.CreateBucketConfiguration{
			LocationConstraint: s3Types.BucketLocationConstraint(REGION),
		},
	})
	if err != nil {
		return hostedZoneId, fmt.Errorf("setupDanglingCNAME: CreateBucket failed: %w", err)
	}

	bucketFQDN := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucketName, REGION)
	_, err = r53Client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneId),
		ChangeBatch: &route53Types.ChangeBatch{
			Changes: []route53Types.Change{
				{
					Action: route53Types.ChangeActionCreate,
					ResourceRecordSet: &route53Types.ResourceRecordSet{
						Name: aws.String(bucketName),
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
		return hostedZoneId, fmt.Errorf("setupDanglingCNAME: ChangeResourceRecordSets failed: %w", err)
	}

	emptyBucket(ctx, s3Client, bucketName)
	_, err = s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return hostedZoneId, fmt.Errorf("setupDanglingCNAME: DeleteBucket failed: %w", err)
	}

	return hostedZoneId, nil
}

func teardownDanglingCNAME(ctx context.Context, r53Client *route53.Client, s3Client *s3.Client, hostedZoneId string, bucketName string) error {
	if hostedZoneId != "" {
		records, err := r53Client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(hostedZoneId),
		})
		if err != nil {
			slog.Error("teardownDanglingCNAME: ListResourceRecordSets failed", "Error", err.Error())
		} else {
			var changes []route53Types.Change
			for _, rec := range records.ResourceRecordSets {
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
					HostedZoneId: aws.String(hostedZoneId),
					ChangeBatch:  &route53Types.ChangeBatch{Changes: changes},
				})
				if err != nil {
					slog.Error("teardownDanglingCNAME: ChangeResourceRecordSets failed", "Error", err.Error())
				}
			}
		}
		_, err = r53Client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{
			Id: aws.String(hostedZoneId),
		})
		if err != nil {
			slog.Error("teardownDanglingCNAME: DeleteHostedZone failed", "Error", err.Error())
		}
	}

	emptyBucket(ctx, s3Client, bucketName)
	_, err := s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	// The bucket is intentionally deleted by setupDanglingCNAME to create the
	// dangling state, so a NoSuchBucket error here is expected on the happy path.
	var nsb *s3Types.NoSuchBucket
	if err != nil && !errors.As(err, &nsb) {
		slog.Error("teardownDanglingCNAME: DeleteBucket failed", "Error", err.Error())
		return err
	}
	return nil
}

func runUnhappyPathCheck(_ context.Context) error {
	// Use a background context for the entire self-test so setup/scan are not
	// cancelled if the Lambda handler context is close to its deadline.
	ctx := context.Background()

	dnsZone, bucketName, err := generateTestNames()
	if err != nil {
		return err
	}
	slog.Info("Unhappy path check: starting", "dnsZone", dnsZone)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: LoadDefaultConfig failed: %w", err)
	}

	r53Client := route53.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.Region = REGION })
	ebsClient := elasticbeanstalk.NewFromConfig(cfg)

	hostedZoneId, err := setupDanglingCNAME(ctx, r53Client, s3Client, dnsZone, bucketName)
	defer func() {
		if teardownErr := teardownDanglingCNAME(ctx, r53Client, s3Client, hostedZoneId, bucketName); teardownErr != nil {
			slog.Error("runUnhappyPathCheck: teardown failed", "Error", teardownErr.Error())
		}
	}()
	if err != nil {
		return err
	}

	danglingMap := make(map[string]*ExtractedResult)
	awsResources := make(map[string]bool)

	_, err = listPotentialVulnerableDNSRecord(r53Client, danglingMap)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: listPotentialVulnerableDNSRecord failed: %w", err)
	}
	err = listS3Buckets(s3Client, awsResources)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: listS3Buckets failed: %w", err)
	}
	err = listEBSEnvironment(ebsClient, awsResources)
	if err != nil {
		return fmt.Errorf("runUnhappyPathCheck: listEBSEnvironment failed: %w", err)
	}

	_, vulnerableItems := verifyTakeover(danglingMap, awsResources)

	var testZoneItems []string
	for _, item := range vulnerableItems {
		if strings.Contains(item, dnsZone) {
			testZoneItems = append(testZoneItems, item)
		}
	}
	slog.Info("Unhappy path check: detection complete", "vulnerableItems", len(testZoneItems))

	if len(testZoneItems) == 0 {
		return slack.SendSlackNotification(os.Getenv("CHANNEL_ID_DEBUG"), fmt.Sprintf("Self-test FAILED: dangling record in %s for test zone %s was NOT detected.", AWS_ORG, dnsZone))
	}

	return nil
}
