package main

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestGenerateTestNames(t *testing.T) {
	t.Parallel()

	dnsZone, bucketName, err := generateTestNames()
	if err != nil {
		log.Fatalln(err)
	}

	if !strings.HasSuffix(dnsZone, ".net") {
		t.Errorf("dnsZone should end with .net, got %s", dnsZone)
	}
	// hex(6 bytes) = 12 chars + ".net" = 16 chars
	if len(dnsZone) != 16 {
		t.Errorf("dnsZone length should be 16, got %d (%s)", len(dnsZone), dnsZone)
	}
	hexPart := strings.TrimSuffix(dnsZone, ".net")
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hex prefix contains non-hex character %q in %s", c, hexPart)
		}
	}
	if want := "subdomain." + dnsZone; bucketName != want {
		t.Errorf("bucketName = %s, want %s", bucketName, want)
	}
}

func TestGenerateTestNamesUniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	for i := range 50 {
		dnsZone, _, err := generateTestNames()
		if err != nil {
			log.Fatalln(err)
		}
		if _, dup := seen[dnsZone]; dup {
			t.Fatalf("duplicate dnsZone after %d iterations: %s", i, dnsZone)
		}
		seen[dnsZone] = struct{}{}
	}
}

func TestVerifyTakeover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		dnsZonesPointingToAWS map[string]*ExtractedResult
		awsResources          map[string]bool
		wantTakeover          []*ExtractedResult
		wantVulnerableItems   []string
	}{
		{
			name: "EBS dangling",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			awsResources: map[string]bool{
				"images.example.com": true,
			},
			wantTakeover: []*ExtractedResult{
				{
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			wantVulnerableItems: []string{
				"test23 -> test23.eu-south-1.elasticbeanstalk.com",
			},
		},
		{
			name: "EBS exists - not vulnerable",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			awsResources: map[string]bool{
				"test23.eu-south-1.elasticbeanstalk.com": true,
			},
			wantTakeover:        nil,
			wantVulnerableItems: nil,
		},
		{
			name: "S3 dangling",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"images.example.com": {
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			awsResources: map[string]bool{
				"test23.eu-south-1.elasticbeanstalk.com": true,
			},
			wantTakeover: []*ExtractedResult{
				{
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			wantVulnerableItems: []string{
				"images.example.com -> images.example.com.s3.us-east-1.amazonaws.com",
			},
		},
		{
			name: "S3 exists - not vulnerable",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"images.example.com": {
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			awsResources: map[string]bool{
				"images.example.com": true,
			},
			wantTakeover:        nil,
			wantVulnerableItems: nil,
		},
		{
			name:                  "empty DNS zones",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{},
			awsResources:          map[string]bool{"a": true},
			wantTakeover:          nil,
			wantVulnerableItems:   nil,
		},
		{
			name: "multiple vulnerable resources",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"a.s3.amazonaws.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
				"b.s3.amazonaws.com": {Name: "b.example.com", ResourceDNSName: "b.s3.amazonaws.com", Type: "S3"},
				"c.s3.amazonaws.com": {Name: "c.example.com", ResourceDNSName: "c.s3.amazonaws.com", Type: "S3"},
			},
			awsResources: map[string]bool{
				"b.s3.amazonaws.com": true,
			},
			wantTakeover: []*ExtractedResult{
				{Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
				{Name: "c.example.com", ResourceDNSName: "c.s3.amazonaws.com", Type: "S3"},
			},
			wantVulnerableItems: []string{
				"a.example.com -> a.s3.amazonaws.com",
				"c.example.com -> c.s3.amazonaws.com",
			},
		},
		{
			name: "all resources safe",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"a.example.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
				"b.example.com": {Name: "b.example.com", ResourceDNSName: "b.s3.amazonaws.com", Type: "S3"},
			},
			awsResources: map[string]bool{
				"a.example.com": true,
				"b.example.com": true,
			},
			wantTakeover:        nil,
			wantVulnerableItems: nil,
		},
		{
			name: "empty AWS resources - all vulnerable",
			dnsZonesPointingToAWS: map[string]*ExtractedResult{
				"a.example.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
			},
			awsResources: map[string]bool{},
			wantTakeover: []*ExtractedResult{
				{Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
			},
			wantVulnerableItems: []string{
				"a.example.com -> a.s3.amazonaws.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotTakeover, gotItems := verifyTakeover(tt.dnsZonesPointingToAWS, tt.awsResources)

			if len(gotTakeover) != len(tt.wantTakeover) {
				t.Fatalf("verifyTakeover() takeover length = %d, want %d", len(gotTakeover), len(tt.wantTakeover))
			}

			slices.SortFunc(gotTakeover, func(a, b *ExtractedResult) int {
				return strings.Compare(a.ResourceDNSName, b.ResourceDNSName)
			})
			slices.SortFunc(tt.wantTakeover, func(a, b *ExtractedResult) int {
				return strings.Compare(a.ResourceDNSName, b.ResourceDNSName)
			})
			for i := range gotTakeover {
				if *gotTakeover[i] != *tt.wantTakeover[i] {
					t.Errorf("verifyTakeover() takeover[%d] = %+v, want %+v", i, *gotTakeover[i], *tt.wantTakeover[i])
				}
			}

			slices.Sort(gotItems)
			slices.Sort(tt.wantVulnerableItems)
			if len(gotItems) != len(tt.wantVulnerableItems) {
				t.Fatalf("verifyTakeover() items length = %d, want %d", len(gotItems), len(tt.wantVulnerableItems))
			}
			for i := range gotItems {
				if gotItems[i] != tt.wantVulnerableItems[i] {
					t.Errorf("verifyTakeover() items[%d] = %s, want %s", i, gotItems[i], tt.wantVulnerableItems[i])
				}
			}
		})
	}
}

func TestCheckPresenceAwsResource(t *testing.T) {
	t.Parallel()

	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	callerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	recordCount := int64(1)
	ttl := int64(300)

	hostedZone := route53Types.HostedZone{
		CallerReference:        &callerReference,
		Id:                     &hostedZoneId,
		Name:                   &hostedZoneName,
		ResourceRecordSetCount: &recordCount,
	}

	tests := []struct {
		name        string
		recordName  string
		recordValue string
		wantKey     string
		wantType    string
		wantFound   bool
	}{
		{
			name:        "S3 record with scheme",
			recordName:  "test.pippopluto.net",
			recordValue: "https://test.pippopluto.net.s3.eu-south-1.amazonaws.com",
			wantKey:     "test.pippopluto.net",
			wantType:    "S3",
			wantFound:   true,
		},
		{
			name:        "S3 record plain hostname",
			recordName:  "test.pippopluto.net",
			recordValue: "test.pippopluto.net.s3.eu-south-1.amazonaws.com",
			wantKey:     "test.pippopluto.net",
			wantType:    "S3",
			wantFound:   true,
		},
		{
			name:        "EBS record with scheme",
			recordName:  "test23.pippopluto.net",
			recordValue: "https://test23.eu-south-1.elasticbeanstalk.com",
			wantKey:     "test23.eu-south-1.elasticbeanstalk.com",
			wantType:    "Elasticbeanstalk",
			wantFound:   true,
		},
		{
			name:        "EBS record plain hostname",
			recordName:  "test23.pippopluto.net",
			recordValue: "test23.eu-south-1.elasticbeanstalk.com",
			wantKey:     "test23.eu-south-1.elasticbeanstalk.com",
			wantType:    "Elasticbeanstalk",
			wantFound:   true,
		},
		{
			name:        "non-vulnerable record is ignored",
			recordName:  "test.pippopluto.net",
			recordValue: "something.cloudfront.net",
			wantFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			record := &route53Types.ResourceRecordSet{
				Name: &tt.recordName,
				Type: route53Types.RRTypeCname,
				ResourceRecords: []route53Types.ResourceRecord{
					{Value: &tt.recordValue},
				},
				TTL: &ttl,
			}
			output := make(map[string]*ExtractedResult)
			checkPresenceAwsResource(record, hostedZone, output)

			if !tt.wantFound {
				if len(output) != 0 {
					t.Errorf("expected empty output, got %d entries", len(output))
				}
				return
			}

			result, exists := output[tt.wantKey]
			if !exists {
				t.Fatalf("expected key %q in output", tt.wantKey)
			}
			if result.Type != tt.wantType {
				t.Errorf("type = %s, want %s", result.Type, tt.wantType)
			}
			if result.HostedZoneName != hostedZoneName {
				t.Errorf("HostedZoneName = %s, want %s", result.HostedZoneName, hostedZoneName)
			}
			if result.HostedZoneId != hostedZoneId {
				t.Errorf("HostedZoneId = %s, want %s", result.HostedZoneId, hostedZoneId)
			}
		})
	}
}

func TestExtractCNAMERecords(t *testing.T) {
	t.Parallel()

	callerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	recordCount := int64(1)

	hostedZone := route53Types.HostedZone{
		CallerReference:        &callerReference,
		Id:                     &hostedZoneId,
		Name:                   &hostedZoneName,
		ResourceRecordSetCount: &recordCount,
	}

	tests := []struct {
		name       string
		recordSets []route53Types.ResourceRecordSet
		wantCount  int
		wantKeys   []string
	}{
		{
			name: "EBS CNAME detected",
			recordSets: []route53Types.ResourceRecordSet{
				cnameRecord("test23.pippopluto.net", "test23.eu-south-1.elasticbeanstalk.com"),
			},
			wantCount: 1,
			wantKeys:  []string{"test23.eu-south-1.elasticbeanstalk.com"},
		},
		{
			name: "S3 CNAME detected",
			recordSets: []route53Types.ResourceRecordSet{
				cnameRecord("images.example.com", "images.example.com.s3.us-east-1.amazonaws.com"),
			},
			wantCount: 1,
			wantKeys:  []string{"images.example.com"},
		},
		{
			name: "non-CNAME record skipped",
			recordSets: []route53Types.ResourceRecordSet{
				aRecord("test.pippopluto.net", "1.2.3.4"),
			},
			wantCount: 0,
		},
		{
			name: "non-vulnerable CNAME skipped",
			recordSets: []route53Types.ResourceRecordSet{
				cnameRecord("cdn.pippopluto.net", "something.cloudfront.net"),
			},
			wantCount: 0,
		},
		{
			name:       "empty record set",
			recordSets: []route53Types.ResourceRecordSet{},
			wantCount:  0,
		},
		{
			name: "mixed records - only vulnerable CNAMEs extracted",
			recordSets: []route53Types.ResourceRecordSet{
				aRecord("www.pippopluto.net", "1.2.3.4"),
				cnameRecord("cdn.pippopluto.net", "something.cloudfront.net"),
				cnameRecord("images.pippopluto.net", "images.pippopluto.net.s3.eu-south-1.amazonaws.com"),
				cnameRecord("api.pippopluto.net", "api.eu-south-1.elasticbeanstalk.com"),
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recordSetsOutput := &route53.ListResourceRecordSetsOutput{
				IsTruncated:        false,
				ResourceRecordSets: tt.recordSets,
			}
			result := extractCNAMERecords(recordSetsOutput, hostedZone)

			if len(result) != tt.wantCount {
				t.Fatalf("len(result) = %d, want %d", len(result), tt.wantCount)
			}
			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("expected key %q in result", key)
				}
			}
		})
	}
}

func TestProcessMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid accounts - AssumeRole error is logged not returned",
			body:    marshalAccounts("637423468901", "ppa-subdomain-dev"),
			wantErr: false,
		},
		{
			name:    "invalid JSON body",
			body:    "not json",
			wantErr: true,
		},
		{
			name:    "empty JSON array",
			body:    "[]",
			wantErr: false,
		},
		{
			name:    "multiple accounts",
			body:    marshalMultipleAccounts([]string{"111111111111", "222222222222"}, []string{"account-1", "account-2"}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := processMessage(events.SQSMessage{Body: tt.body})
			if (err != nil) != tt.wantErr {
				t.Errorf("processMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunUnhappyPathCheckFailsGracefully(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	err := runUnhappyPathCheck(ctx)
	if err == nil {
		t.Error("runUnhappyPathCheck() should return error without valid AWS credentials")
	}
}

// helpers

func cnameRecord(name, value string) route53Types.ResourceRecordSet {
	return route53Types.ResourceRecordSet{
		Name: &name,
		Type: route53Types.RRTypeCname,
		ResourceRecords: []route53Types.ResourceRecord{
			{Value: &value},
		},
	}
}

func aRecord(name, value string) route53Types.ResourceRecordSet {
	return route53Types.ResourceRecordSet{
		Name: &name,
		Type: route53Types.RRTypeA,
		ResourceRecords: []route53Types.ResourceRecord{
			{Value: &value},
		},
	}
}

func marshalAccounts(id, name string) string {
	accounts, _ := json.Marshal(&[]types.Account{
		{Id: &id, Name: &name},
	})
	return string(accounts)
}

func marshalMultipleAccounts(ids, names []string) string {
	var accounts []types.Account
	for i := range ids {
		accounts = append(accounts, types.Account{Id: &ids[i], Name: &names[i]})
	}
	data, _ := json.Marshal(&accounts)
	return string(data)
}
