package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebsTypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestVerifyTakeover(t *testing.T) {
	tests := []struct {
		TestName                     string
		DNSZonesPoitingToAWSResource map[string]*ExtractedResult
		AWSResources                 map[string]bool
		WantSubdomainTakeover        []*ExtractedResult
		WantVulnerableItems          []string
	}{
		{
			TestName: "Test 1",
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
			TestName: "Test 2",
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
			TestName: "Test 3",
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
			TestName: "Test 4",
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

func TestCheckPresenceAwsResource(t *testing.T) {
	recordNameS3 := "test.pippopluto.net"
	recordNameEBS := "test23.pippopluto.net"
	recordValueS3 := "https://test.pippopluto.net.s3.eu-south-1.amazonaws.com"
	recordValueEBS := "https://test23.eu-south-1.elasticbeanstalk.com"
	CallerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	ttl := int64(300)
	recordCount := int64(1)
	tests := []struct {
		TestName              string
		Record                *route53Types.ResourceRecordSet
		HostedZone            route53Types.HostedZone
		WantAWSResourceOutput map[string]*ExtractedResult
	}{
		{
			TestName: "Test 1",
			Record: &route53Types.ResourceRecordSet{
				Name:                 &recordNameS3,
				Type:                 route53Types.RRTypeCname,
				AliasTarget:          nil,
				CidrRoutingConfig:    nil,
				Failover:             "",
				GeoLocation:          nil,
				GeoProximityLocation: nil,
				HealthCheckId:        nil,
				MultiValueAnswer:     nil,
				Region:               "",
				ResourceRecords: []route53Types.ResourceRecord{
					{Value: &recordValueS3},
				},
				SetIdentifier:           nil,
				TTL:                     &ttl,
				TrafficPolicyInstanceId: nil,
				Weight:                  nil,
			},
			HostedZone: route53Types.HostedZone{
				CallerReference:        &CallerReference,
				Id:                     &hostedZoneId,
				Name:                   &hostedZoneName,
				Config:                 nil,
				LinkedService:          nil,
				ResourceRecordSetCount: &recordCount,
			},
			WantAWSResourceOutput: map[string]*ExtractedResult{
				recordNameS3: {
					Name:            recordNameS3,
					ResourceDNSName: "images.example.com.s3.us-east-1.amazonaws.com",
					Found:           true,
					HostedZoneName:  hostedZoneName,
					HostedZoneId:    hostedZoneId,
					Type:            "S3",
				},
			},
		},
		{
			TestName: "Test 2",
			Record: &route53Types.ResourceRecordSet{
				Name:                 &recordNameEBS,
				Type:                 route53Types.RRTypeCname,
				AliasTarget:          nil,
				CidrRoutingConfig:    nil,
				Failover:             "",
				GeoLocation:          nil,
				GeoProximityLocation: nil,
				HealthCheckId:        nil,
				MultiValueAnswer:     nil,
				Region:               "",
				ResourceRecords: []route53Types.ResourceRecord{
					{Value: &recordValueEBS},
				},
				SetIdentifier:           nil,
				TTL:                     &ttl,
				TrafficPolicyInstanceId: nil,
				Weight:                  nil,
			},
			HostedZone: route53Types.HostedZone{
				CallerReference:        &CallerReference,
				Id:                     &hostedZoneId,
				Name:                   &hostedZoneName,
				Config:                 nil,
				LinkedService:          nil,
				ResourceRecordSetCount: &recordCount,
			},
			WantAWSResourceOutput: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            recordNameEBS,
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  hostedZoneName,
					HostedZoneId:    hostedZoneId,
					Type:            "Elasticbeanstalk",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			checkPresenceAwsResource(tt.Record, tt.HostedZone, tt.WantAWSResourceOutput)
		})
	}
}

func TestExtractCNAMERecords(t *testing.T) {
	recordNameEBS := "test23.pippopluto.net"
	recordValueEBS := "https://test23.eu-south-1.elasticbeanstalk.com"
	CallerReference := "ef87410c-bceb-4260-951d-b44fcd1f0683"
	hostedZoneName := "pippopluto.it"
	hostedZoneId := "/hostedzone/Z102849618Q4NTO59GFR4"
	recordCount := int64(1)

	tests := []struct {
		TestName                   string
		RecordSetsOutput           *route53.ListResourceRecordSetsOutput
		HostedZone                 route53Types.HostedZone
		WantPossibleDanglingRecord map[string]*ExtractedResult
	}{
		{
			TestName: "Test 1",
			RecordSetsOutput: &route53.ListResourceRecordSetsOutput{
				IsTruncated: false,
				MaxItems:    nil,
				ResourceRecordSets: []route53Types.ResourceRecordSet{
					{
						Name:                 &recordNameEBS,
						Type:                 route53Types.RRTypeCname,
						AliasTarget:          nil,
						CidrRoutingConfig:    nil,
						Failover:             "",
						GeoLocation:          nil,
						GeoProximityLocation: nil,
						HealthCheckId:        nil,
						MultiValueAnswer:     nil,
						Region:               "",
						ResourceRecords: []route53Types.ResourceRecord{
							{Value: &recordValueEBS},
						},
						SetIdentifier:           nil,
						TTL:                     nil,
						TrafficPolicyInstanceId: nil,
						Weight:                  nil,
					},
				},
			},
			HostedZone: route53Types.HostedZone{
				CallerReference:        &CallerReference,
				Id:                     &hostedZoneId,
				Name:                   &hostedZoneName,
				Config:                 nil,
				LinkedService:          nil,
				ResourceRecordSetCount: &recordCount,
			},
			WantPossibleDanglingRecord: map[string]*ExtractedResult{
				"test23.eu-south-1.elasticbeanstalk.com": {
					Name:            recordNameEBS,
					ResourceDNSName: "test23.eu-south-1.elasticbeanstalk.com",
					Found:           true,
					HostedZoneName:  hostedZoneName,
					HostedZoneId:    hostedZoneId,
					Type:            "Elasticbeanstalk",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			gotPossibleDanglingRecord := extractCNAMERecords(tt.RecordSetsOutput, tt.HostedZone)
			got, _ := json.Marshal(gotPossibleDanglingRecord)
			want, _ := json.Marshal(tt.WantPossibleDanglingRecord)
			if string(got) != string(want) {
				t.Errorf("step 1 - extractCNAMERecords() = %v, want %v", string(got), string(want))
			}
		})
	}
}

func TestProcessMessage(t *testing.T) {
	accountId := "637423468901"
	name := "ppa-subdomain-dev"
	awsAccount, _ := json.Marshal(&[]types.Account{
		{Id: &accountId, Name: &name},
	})
	tests := []struct {
		TestName           string
		Record             events.SQSMessage
		WantVulnerableItem []string
		WantError          error
		WantErrorCondition bool
	}{
		{
			TestName: "Test 1 - Error Case",
			Record: events.SQSMessage{
				Body: string(awsAccount),
			},
			WantVulnerableItem: nil,
			WantError:          nil,
			WantErrorCondition: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			_, err := processMessage(tt.Record)
			if tt.WantErrorCondition && tt.WantError != err {
				t.Errorf("processMessage() = %v, want %v", err, tt.WantError)
			}
		})
	}
}

type mockEBSClient struct {
	output *elasticbeanstalk.DescribeEnvironmentsOutput
	err    error
}

func (m *mockEBSClient) DescribeEnvironments(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestListEBSEnvironment(t *testing.T) {
	tests := []struct {
		TestName string
		Client   *mockEBSClient
		Want     map[string]bool
		WantErr  bool
	}{
		{
			TestName: "keeps active CNAMEs and skips terminated or nil",
			Client: &mockEBSClient{output: &elasticbeanstalk.DescribeEnvironmentsOutput{
				Environments: []ebsTypes.EnvironmentDescription{
					{CNAME: aws.String("Active.eu-south-1.elasticbeanstalk.com"), Status: ebsTypes.EnvironmentStatusReady},
					{CNAME: aws.String("gone.eu-south-1.elasticbeanstalk.com"), Status: ebsTypes.EnvironmentStatusTerminated},
					{CNAME: nil, Status: ebsTypes.EnvironmentStatusReady},
				},
			}},
			Want: map[string]bool{
				"active.eu-south-1.elasticbeanstalk.com": true, // lowercased
			},
		},
		{
			TestName: "no environments yields empty set",
			Client:   &mockEBSClient{output: &elasticbeanstalk.DescribeEnvironmentsOutput{}},
			Want:     map[string]bool{},
		},
		{
			TestName: "describe error is returned",
			Client:   &mockEBSClient{err: errors.New("boom")},
			WantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestName, func(t *testing.T) {
			got := make(map[string]bool)
			err := listEBSEnvironment(tt.Client, got)
			if tt.WantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.Want) {
				t.Fatalf("got %v, want %v", got, tt.Want)
			}
			for k := range tt.Want {
				if !got[k] {
					t.Errorf("missing key %q in %v", k, got)
				}
			}
		})
	}
}
