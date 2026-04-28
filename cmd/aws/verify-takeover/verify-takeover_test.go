package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// ---------------------------------------------------------------------------
// generateTestNames
// ---------------------------------------------------------------------------

func TestGenerateTestNames(t *testing.T) {
	dnsZone, bucketName := generateTestNames()

	if !strings.HasSuffix(dnsZone, ".net") {
		t.Errorf("dnsZone should end with .net, got %s", dnsZone)
	}
	// hex(6 bytes) = 12 chars + ".net" = 16 chars
	if len(dnsZone) != 16 {
		t.Errorf("dnsZone length should be 16, got %d (%s)", len(dnsZone), dnsZone)
	}
	expectedBucket := "subdomain." + dnsZone
	if bucketName != expectedBucket {
		t.Errorf("bucketName should be %s, got %s", expectedBucket, bucketName)
	}

	// Verify uniqueness across two calls
	dnsZone2, _ := generateTestNames()
	if dnsZone == dnsZone2 {
		t.Errorf("generateTestNames should produce unique names, got same value twice: %s", dnsZone)
	}
}

func TestGenerateTestNamesFormat(t *testing.T) {
	dnsZone, bucketName := generateTestNames()

	hexPart := strings.TrimSuffix(dnsZone, ".net")
	if len(hexPart) != 12 {
		t.Errorf("hex prefix should be 12 chars, got %d (%s)", len(hexPart), hexPart)
	}
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hex prefix contains non-hex character %q in %s", c, hexPart)
		}
	}
	if bucketName != "subdomain."+dnsZone {
		t.Errorf("bucketName mismatch: got %s, want subdomain.%s", bucketName, dnsZone)
	}
}

func TestGenerateTestNamesUniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		dnsZone, _ := generateTestNames()
		if _, dup := seen[dnsZone]; dup {
			t.Errorf("duplicate dnsZone after %d iterations: %s", i, dnsZone)
		}
		seen[dnsZone] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// verifyTakeover
// ---------------------------------------------------------------------------

func TestVerifyTakeover(t *testing.T) {
	tests := []struct {
		TestName                     string
		DNSZonesPoitingToAWSResource map[string]*ExtractedResult
		AWSResources                 map[string]bool
		WantSubdomainTakeover        []*ExtractedResult
		WantVulnerableItems          []string
	}{
		{
			TestName: "EBS dangling",
			DNSZonesPoitingToAWSResource: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			AWSResources: map[string]bool{
				"images.example.com": true,
			},
			WantSubdomainTakeover: []*ExtractedResult{
				{
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			WantVulnerableItems: []string{
				"test23 -> test23.eu-south-1.elasticbeanstalk.com",
			},
		},
		{
			TestName: "EBS exists - not vulnerable",
			DNSZonesPoitingToAWSResource: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            "test23",
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "Elasticbeanstalk",
				},
			},
			AWSResources: map[string]bool{
				"test23.eu-south-1.elasticbeanstalk.com": true,
			},
			WantSubdomainTakeover: nil,
			WantVulnerableItems:   nil,
		},
		{
			TestName: "S3 dangling",
			DNSZonesPoitingToAWSResource: map[string]*ExtractedResult{
				"images.example.com": {
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			AWSResources: map[string]bool{
				"test23.eu-south-1.elasticbeanstalk.com": true,
			},
			WantSubdomainTakeover: []*ExtractedResult{
				{
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			WantVulnerableItems: []string{
				"images.example.com -> images.example.com.s3.us-east-1.amazonaws.com",
			},
		},
		{
			TestName: "S3 exists - not vulnerable",
			DNSZonesPoitingToAWSResource: map[string]*ExtractedResult{
				"images.example.com": {
					Name:            "images.example.com",
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  "pippopluto.net",
					HostedZoneId:    "/hostedzone/Z102849618Q4NTO59GFR4",
					Type:            "S3",
				},
			},
			AWSResources: map[string]bool{
				"images.example.com": true,
			},
			WantSubdomainTakeover: nil,
			WantVulnerableItems:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			gotSubdomainTakeover, gotVulnerableItems := verifyTakeover(tt.DNSZonesPoitingToAWSResource, tt.AWSResources)
			got, _ := json.Marshal(gotSubdomainTakeover)
			want, _ := json.Marshal(tt.WantSubdomainTakeover)
			if string(got) != string(want) {
				t.Errorf("step 1 - verifyTakeover() = %v, want %v", string(got), string(want))
			}
			got, _ = json.Marshal(gotVulnerableItems)
			want, _ = json.Marshal(tt.WantVulnerableItems)
			if string(got) != string(want) {
				t.Errorf("step 2 - verifyTakeover() = %v, want %v", string(got), string(want))
			}
		})
	}
}

func TestVerifyTakeoverEmpty(t *testing.T) {
	sub, items := verifyTakeover(map[string]*ExtractedResult{}, map[string]bool{"a": true})
	if len(sub) != 0 || len(items) != 0 {
		t.Errorf("expected empty results, got %d sub / %d items", len(sub), len(items))
	}
}

func TestVerifyTakeoverMultipleVulnerable(t *testing.T) {
	dns := map[string]*ExtractedResult{
		"a.example.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
		"b.example.com": {Name: "b.example.com", ResourceDNSName: "b.s3.amazonaws.com", Type: "S3"},
		"c.example.com": {Name: "c.example.com", ResourceDNSName: "c.s3.amazonaws.com", Type: "S3"},
	}
	aws := map[string]bool{
		"b.example.com": true,
	}
	sub, items := verifyTakeover(dns, aws)
	if len(sub) != 2 || len(items) != 2 {
		t.Errorf("expected 2 vulnerable, got %d sub / %d items", len(sub), len(items))
	}
}

func TestVerifyTakeoverAllSafe(t *testing.T) {
	dns := map[string]*ExtractedResult{
		"a.example.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
		"b.example.com": {Name: "b.example.com", ResourceDNSName: "b.s3.amazonaws.com", Type: "S3"},
	}
	aws := map[string]bool{
		"a.example.com": true,
		"b.example.com": true,
	}
	sub, items := verifyTakeover(dns, aws)
	if len(sub) != 0 || len(items) != 0 {
		t.Errorf("expected 0 vulnerable, got %d sub / %d items", len(sub), len(items))
	}
}

func TestVerifyTakeoverEmptyAWSResources(t *testing.T) {
	dns := map[string]*ExtractedResult{
		"a.example.com": {Name: "a.example.com", ResourceDNSName: "a.s3.amazonaws.com", Type: "S3"},
	}
	aws := map[string]bool{}
	sub, items := verifyTakeover(dns, aws)
	if len(sub) != 1 || len(items) != 1 {
		t.Errorf("expected 1 vulnerable, got %d sub / %d items", len(sub), len(items))
	}
}

// ---------------------------------------------------------------------------
// checkPresenceAwsResource
// ---------------------------------------------------------------------------

func TestCheckPresenceAwsResource(t *testing.T) {
	CallerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	ttl := int64(300)
	recordCount := int64(1)

	hostedZone := route53Types.HostedZone{
		CallerReference:        &CallerReference,
		Id:                     &hostedZoneId,
		Name:                   &hostedZoneName,
		Config:                 nil,
		LinkedService:          nil,
		ResourceRecordSetCount: &recordCount,
	}

	t.Run("S3 record", func(t *testing.T) {
		recordName := "test.pippopluto.net"
		recordValue := "https://test.pippopluto.net.s3.eu-south-1.amazonaws.com"
		record := &route53Types.ResourceRecordSet{
			Name: &recordName,
			Type: route53Types.RRTypeCname,
			ResourceRecords: []route53Types.ResourceRecord{
				{Value: &recordValue},
			},
			TTL: &ttl,
		}
		output := make(map[string]*ExtractedResult)
		checkPresenceAwsResource(record, hostedZone, output)
		result, exists := output[recordName]
		if !exists {
			t.Fatal("expected S3 record to be added to output map")
		}
		if result.Type != "S3" {
			t.Errorf("expected type S3, got %s", result.Type)
		}
		if result.Name != recordName {
			t.Errorf("expected name %s, got %s", recordName, result.Name)
		}
		if !result.Found {
			t.Error("expected Found to be true")
		}
		if result.HostedZoneName != hostedZoneName {
			t.Errorf("expected HostedZoneName %s, got %s", hostedZoneName, result.HostedZoneName)
		}
		if result.HostedZoneId != hostedZoneId {
			t.Errorf("expected HostedZoneId %s, got %s", hostedZoneId, result.HostedZoneId)
		}
	})

	t.Run("EBS record", func(t *testing.T) {
		recordName := "test23.pippopluto.net"
		recordValue := "https://test23.eu-south-1.elasticbeanstalk.com"
		record := &route53Types.ResourceRecordSet{
			Name: &recordName,
			Type: route53Types.RRTypeCname,
			ResourceRecords: []route53Types.ResourceRecord{
				{Value: &recordValue},
			},
			TTL: &ttl,
		}
		output := make(map[string]*ExtractedResult)
		checkPresenceAwsResource(record, hostedZone, output)
		result, exists := output["test23.eu-south-1.elasticbeanstalk.com"]
		if !exists {
			t.Fatal("expected EBS record to be added to output map keyed by CNAME")
		}
		if result.Type != "Elasticbeanstalk" {
			t.Errorf("expected type Elasticbeanstalk, got %s", result.Type)
		}
		if result.Name != strings.ToLower(recordName) {
			t.Errorf("expected name %s, got %s", strings.ToLower(recordName), result.Name)
		}
	})

	t.Run("Non-vulnerable record is ignored", func(t *testing.T) {
		recordName := "test.pippopluto.net"
		recordValue := "https://something.cloudfront.net"
		record := &route53Types.ResourceRecordSet{
			Name: &recordName,
			Type: route53Types.RRTypeCname,
			ResourceRecords: []route53Types.ResourceRecord{
				{Value: &recordValue},
			},
			TTL: &ttl,
		}
		output := make(map[string]*ExtractedResult)
		checkPresenceAwsResource(record, hostedZone, output)
		if len(output) != 0 {
			t.Errorf("expected no output for non-vulnerable record, got %d entries", len(output))
		}
	})
}

// ---------------------------------------------------------------------------
// extractCNAMERecords
// ---------------------------------------------------------------------------

func TestExtractCNAMERecords(t *testing.T) {
	CallerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	recordCount := int64(1)

	hostedZone := route53Types.HostedZone{
		CallerReference:        &CallerReference,
		Id:                     &hostedZoneId,
		Name:                   &hostedZoneName,
		Config:                 nil,
		LinkedService:          nil,
		ResourceRecordSetCount: &recordCount,
	}

	t.Run("EBS CNAME detected", func(t *testing.T) {
		recordName := "test23.pippopluto.net"
		recordValue := "https://test23.eu-south-1.elasticbeanstalk.com"
		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated: false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{
				{
					Name: &recordName,
					Type: route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{
						{Value: &recordValue},
					},
				},
			},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 1 {
			t.Fatalf("expected 1 result, got %d", len(result))
		}
		if _, ok := result["test23.eu-south-1.elasticbeanstalk.com"]; !ok {
			t.Error("expected EBS CNAME key in result")
		}
	})

	t.Run("S3 CNAME detected", func(t *testing.T) {
		recordName := "images.example.com"
		recordValue := "https://images.example.com.s3.us-east-1.amazonaws.com"
		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated: false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{
				{
					Name: &recordName,
					Type: route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{
						{Value: &recordValue},
					},
				},
			},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 1 {
			t.Fatalf("expected 1 result, got %d", len(result))
		}
		if _, ok := result[recordName]; !ok {
			t.Error("expected S3 CNAME key in result")
		}
	})

	t.Run("Non-CNAME record skipped", func(t *testing.T) {
		recordName := "test.pippopluto.net"
		recordValue := "1.2.3.4"
		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated: false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{
				{
					Name: &recordName,
					Type: route53Types.RRTypeA,
					ResourceRecords: []route53Types.ResourceRecord{
						{Value: &recordValue},
					},
				},
			},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 0 {
			t.Errorf("expected 0 results for A record, got %d", len(result))
		}
	})

	t.Run("Non-vulnerable CNAME skipped", func(t *testing.T) {
		recordName := "cdn.pippopluto.net"
		recordValue := "https://something.cloudfront.net"
		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated: false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{
				{
					Name: &recordName,
					Type: route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{
						{Value: &recordValue},
					},
				},
			},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 0 {
			t.Errorf("expected 0 results for non-vulnerable CNAME, got %d", len(result))
		}
	})

	t.Run("Empty record set", func(t *testing.T) {
		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated:        false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 0 {
			t.Errorf("expected 0 results for empty record set, got %d", len(result))
		}
	})

	t.Run("Mixed records - only vulnerable CNAMEs extracted", func(t *testing.T) {
		aRecordName := "www.pippopluto.net"
		aRecordValue := "1.2.3.4"
		cnameNonVulnName := "cdn.pippopluto.net"
		cnameNonVulnValue := "https://something.cloudfront.net"
		cnameS3Name := "images.pippopluto.net"
		cnameS3Value := "https://images.pippopluto.net.s3.eu-south-1.amazonaws.com"
		cnameEBSName := "api.pippopluto.net"
		cnameEBSValue := "https://api.eu-south-1.elasticbeanstalk.com"

		recordSetsOutput := &route53.ListResourceRecordSetsOutput{
			IsTruncated: false,
			ResourceRecordSets: []route53Types.ResourceRecordSet{
				{
					Name:            &aRecordName,
					Type:            route53Types.RRTypeA,
					ResourceRecords: []route53Types.ResourceRecord{{Value: &aRecordValue}},
				},
				{
					Name:            &cnameNonVulnName,
					Type:            route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{{Value: &cnameNonVulnValue}},
				},
				{
					Name:            &cnameS3Name,
					Type:            route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{{Value: &cnameS3Value}},
				},
				{
					Name:            &cnameEBSName,
					Type:            route53Types.RRTypeCname,
					ResourceRecords: []route53Types.ResourceRecord{{Value: &cnameEBSValue}},
				},
			},
		}
		result := extractCNAMERecords(recordSetsOutput, hostedZone)
		if len(result) != 2 {
			t.Errorf("expected 2 vulnerable CNAMEs, got %d", len(result))
		}
	})
}

// ---------------------------------------------------------------------------
// processMessage
// ---------------------------------------------------------------------------

func TestProcessMessage(t *testing.T) {
	t.Run("Valid accounts - error from AssumeRole", func(t *testing.T) {
		accountId := "637423468901"
		name := "ppa-subdomain-dev"
		awsAccount, _ := json.Marshal(&[]types.Account{
			{Id: &accountId, Name: &name},
		})
		_, err := processMessage(events.SQSMessage{Body: string(awsAccount)})
		// processMessage logs errors but doesn't return them for individual accounts
		if err != nil {
			t.Errorf("processMessage() returned unexpected error: %v", err)
		}
	})

	t.Run("Invalid JSON body", func(t *testing.T) {
		_, err := processMessage(events.SQSMessage{Body: "not json"})
		if err == nil {
			t.Error("processMessage() should return error for invalid JSON")
		}
	})

	t.Run("Empty JSON array", func(t *testing.T) {
		_, err := processMessage(events.SQSMessage{Body: "[]"})
		if err != nil {
			t.Errorf("processMessage() returned unexpected error for empty array: %v", err)
		}
	})

	t.Run("Multiple accounts", func(t *testing.T) {
		id1 := "111111111111"
		name1 := "account-1"
		id2 := "222222222222"
		name2 := "account-2"
		awsAccounts, _ := json.Marshal(&[]types.Account{
			{Id: &id1, Name: &name1},
			{Id: &id2, Name: &name2},
		})
		_, err := processMessage(events.SQSMessage{Body: string(awsAccounts)})
		// Will fail on AssumeRole but should not return error
		if err != nil {
			t.Errorf("processMessage() returned unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// runUnhappyPathCheck
// ---------------------------------------------------------------------------

func TestRunUnhappyPathCheckFailsGracefully(t *testing.T) {
	// Exercises runUnhappyPathCheck, setupDanglingCNAME, teardownDanglingCNAME,
	// and emptyBucket code paths. The call fails on the first real AWS API call
	// (CreateHostedZone) but covers the initialisation and defer cleanup logic.
	ctx := context.Background()
	err := runUnhappyPathCheck(ctx)
	if err == nil {
		t.Error("runUnhappyPathCheck() should return error without valid AWS credentials")
	}
}
