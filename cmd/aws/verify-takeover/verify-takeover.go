package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"subdomain/internal/pkg/slack"

	"net/url"

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
	var vulnerableItemsOrg []string
	var err error
	for _, record := range event.Records {
		vulnerableItemsOrg, err = processMessage(record)
		if err != nil {
			return "", err
		}
	}

	//Send alert on Slack
	err = slack.SendSlackNotification(vulnerableItemsOrg, AWS_ORG)
	if err != nil {
		return "", fmt.Errorf("slack notification failed %v ", err)
	}

	return "Execution completed successfully", nil
}

func main() {
	SetupLogger()
	slog.Info("Starting Lambda")
	lambda.Start(HandleRequest)
}

func SetupLogger() {

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	handler := slog.NewJSONHandler(os.Stderr, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func processMessage(record events.SQSMessage) ([]string, error) {
	accounts := new([]types.Account)
	err := json.Unmarshal([]byte(record.Body), accounts)
	if err != nil {
		return nil, err
	}
	var vulnerableItemsOrg []string
	for _, account := range *accounts {
		vulnerableItemAccount, err := processAccount(&account)
		if err != nil {
			//It does not return because the tool continue with other accounts.
			slog.Error("Error in processing the account....")
			slog.Error(err.Error())
		}
		vulnerableItemsOrg = append(vulnerableItemsOrg, vulnerableItemAccount...)
	}
	return vulnerableItemsOrg, nil
}

func processAccount(account *types.Account) ([]string, error) {
	//Create clients for r53, s3, ebs queries
	r53Client, s3Client, ebsClient, err := createClients(account.Id)
	if err != nil {
		return nil, err
	}
	slog.Info("Clients created")
	DNSZonesPoitingToAWSResource := make(map[string]*ExtractedResult)
	AWSResources := make(map[string]bool)

	//List potential vulnerable CNAME record belonging to the account read from the queue
	err = listPotentialVulnerableDNSRecord(r53Client, DNSZonesPoitingToAWSResource)
	if err != nil {
		return nil, err
	}
	slog.Info("Listed potential vulnerable CNAME record")

	//List S3 buckets belonging to the assumed account
	err = listS3Buckets(s3Client, AWSResources)
	if err != nil {
		return nil, err
	}
	slog.Info("Listed account's S3")
	//List EBS environments belonging to the assumed account
	err = listEBSEnvironment(ebsClient, AWSResources)
	if err != nil {
		return nil, err
	}
	slog.Info(fmt.Sprintf("Resources vulnerable to subdomain takeover for account %s - %s:\n", *account.Name, *account.Id))
	slog.Info("Listed account's EBS")

	//Verify takeover
	vulnerableAWSResources, vulnerableItems := verifyTakeover(DNSZonesPoitingToAWSResource, AWSResources)

	if len(vulnerableAWSResources) > 0 {
		jsonResult, _ := json.Marshal(vulnerableAWSResources)
		*account.Name = strings.ReplaceAll(strings.ReplaceAll(*account.Name, "\n", ""), "\r", "")
		*account.Id = strings.ReplaceAll(strings.ReplaceAll(*account.Id, "\n", ""), "\r", "")

		slog.Info(string(jsonResult))
	}

	return vulnerableItems, nil
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

func listPotentialVulnerableDNSRecord(r53Client *route53.Client, DNSZonesPoitingToAWSResource map[string]*ExtractedResult) error {
	//Pagination ok
	pagination := true
	var nextMarker *string
	var resultDNS []route53Types.HostedZone
	for pagination {
		tempRes, err := r53Client.ListHostedZones(context.TODO(), &route53.ListHostedZonesInput{Marker: nextMarker})
		if err != nil {
			return err
		}
		pagination = tempRes.IsTruncated
		nextMarker = tempRes.NextMarker
		resultDNS = append(resultDNS, tempRes.HostedZones...)
	}
	//Pagination
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
				return err
			}
			pagination = recordSests.IsTruncated
			nextMarker = recordSests.NextRecordIdentifier
			tmpExtractedResultAWSResources = extractCNAMERecords(recordSests, hostedZone)
			maps.Copy(DNSZonesPoitingToAWSResource, tmpExtractedResultAWSResources)
		}
	}
	return nil
}

func checkPresenceAwsResource(record *route53Types.ResourceRecordSet, hostedZone route53Types.HostedZone, AWSResourceOutput map[string]*ExtractedResult) {
	tmpExtractedResult := &ExtractedResult{ResourceDNSName: "", Found: false, Name: "", Type: ""}
	u, _ := url.Parse(*record.ResourceRecords[0].Value)
	tmpExtractedResult.ResourceDNSName = strings.ToLower(u.Host)
	tmpExtractedResult.Found = true
	tmpExtractedResult.Name = strings.ToLower(strings.TrimRight(strings.TrimSpace(*record.Name), "."))
	tmpExtractedResult.HostedZoneName = *hostedZone.Name
	tmpExtractedResult.HostedZoneId = *hostedZone.Id
	if strings.Contains(*record.ResourceRecords[0].Value, S3_RESEARCH_PATTERN) {
		tmpExtractedResult.Type = VULNERABLE_AWS_RESOURCES[0] //S3
		AWSResourceOutput[tmpExtractedResult.Name] = tmpExtractedResult
	} else if strings.Contains(*record.ResourceRecords[0].Value, ELASTIC_BEANSTALK_RESEARCH_PATTERN) {
		tmpExtractedResult.Type = VULNERABLE_AWS_RESOURCES[1] //Elasticbeanstalk
		AWSResourceOutput[tmpExtractedResult.ResourceDNSName] = tmpExtractedResult
	}
}

func extractCNAMERecords(recordSetsOutput *route53.ListResourceRecordSetsOutput, hostedZone route53Types.HostedZone) map[string]*ExtractedResult {
	possibleDanglingRecord := make(map[string]*ExtractedResult)
	for _, record := range recordSetsOutput.ResourceRecordSets {
		//Check only CNAME records
		if record.Type == route53Types.RRTypeCname {
			//Check whether DNS record point to a S3 bucket o EBS env
			if strings.Contains(*record.ResourceRecords[0].Value, S3_RESEARCH_PATTERN) || strings.Contains(*record.ResourceRecords[0].Value, ELASTIC_BEANSTALK_RESEARCH_PATTERN) {
				checkPresenceAwsResource(&record, hostedZone, possibleDanglingRecord)
			}
		}
	}
	return possibleDanglingRecord
}

func listS3Buckets(s3Client *s3.Client, AWSResources map[string]bool) error {
	//Pagination
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
	//Pagination
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
