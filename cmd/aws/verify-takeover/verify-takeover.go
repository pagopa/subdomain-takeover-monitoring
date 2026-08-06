package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"subdomain/internal/pkg/logger"
	"subdomain/internal/pkg/selftest"
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
	slackChannelID := os.Getenv("CHANNEL_ID")
	slackChannelIDDebug := os.Getenv("CHANNEL_ID_DEBUG")

	// Create clients in the Lambda's own account for the self-test canary.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}
	r53OwnClient := route53.NewFromConfig(cfg)
	s3OwnClient := s3.NewFromConfig(cfg, func(o *s3.Options) { o.Region = REGION })

	// Create the canary before scanning so the scan detects it like any other
	// dangling record. Teardown is deferred so the resources are always removed.
	canary, err := selftest.SetupDanglingCNAME(ctx, r53OwnClient, s3OwnClient, REGION)
	defer func() {
		if terr := canary.Teardown(ctx, r53OwnClient, s3OwnClient); terr != nil {
			slog.Error("canary teardown failed", "Error", terr.Error())
		}
	}()
	if err != nil {
		return "", fmt.Errorf("canary setup failed: %w", err)
	}

	var vulnerableItemsOrg []string
	for _, record := range event.Records {
		vulnerableItemsOrg, err = processMessage(record)
		if err != nil {
			return "", err
		}
	}
	slog.Info("Subdomain takeover monitoring tool has correctly verified all AWS accounts belonging to organization.")

	// Separate the real dangling records from the canary planted for the self-test.
	realItems, canaryFound := canary.Split(vulnerableItemsOrg)

	switch {
	case !canaryFound:
		// The scanner failed to detect the canary, so its results cannot be trusted.
		slog.Error("Self-test failed: the canary dangling record was not detected")
		message := fmt.Sprintf("Self-test FAILED in %s: the canary dangling record was not detected, so the scanner may be broken.", AWS_ORG)
		err = slack.SendSlackNotification(slackChannelIDDebug, message)
	case len(realItems) > 0:
		resourceListText := slack.FormatBulletList(realItems)
		message := fmt.Sprintf("Attention: Potentially vulnerable resources detected in %s. These may be susceptible to subdomain takeover.\nThe pointed resources do not seem to belong to the organization. Please remove any dangling DNS records from the hosted zones to mitigate the risk.\n", AWS_ORG)
		err = slack.SendSlackNotification(slackChannelID, message, resourceListText)
	default:
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
			//It does not return because the tool continue with other accounts.
			slog.Error("Error in processing the account....", "Error", err.Error())
		}
		vulnerableItemsOrg = append(vulnerableItemsOrg, vulnerableItemAccount...)
		slog.Info("Listing DNS Record for each account...", "Account: ", account.Name, "DNS Records: ", accountDNSRecord)
	}
	return vulnerableItemsOrg, nil
}

func processAccount(account *types.Account) ([]string, map[string]*route53.ListResourceRecordSetsOutput, error) {
	//Create clients for r53, s3, ebs queries
	r53Client, s3Client, ebsClient, err := createClients(account.Id)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Clients created")
	DNSZonesPoitingToAWSResource := make(map[string]*ExtractedResult)
	AWSResources := make(map[string]bool)

	//List potential vulnerable CNAME record belonging to the account read from the queue
	accountDNSRecord, err := listPotentialVulnerableDNSRecord(r53Client, DNSZonesPoitingToAWSResource)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Listed potential vulnerable CNAME record")

	//List S3 buckets belonging to the assumed account
	err = listS3Buckets(s3Client, AWSResources)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug("Listed account's S3")
	//List EBS environments belonging to the assumed account
	err = listEBSEnvironment(ebsClient, AWSResources)
	if err != nil {
		return nil, nil, err
	}
	slog.Debug(fmt.Sprintf("Resources vulnerable to subdomain takeover for account %s - %s:\n", *account.Name, *account.Id))
	slog.Debug("Listed account's EBS")

	//Verify takeover
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
	//Pagination ok
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

func checkPresenceAwsResource(record *route53Types.ResourceRecordSet, hostedZone route53Types.HostedZone, AWSResourceOutput map[string]*ExtractedResult) {
	tmpExtractedResult := &ExtractedResult{ResourceDNSName: "", Found: false, Name: "", Type: ""}
	// CNAME values have no scheme, so prepend "//" (when absent) to make url.Parse
	// populate Host instead of dumping the whole value into Path.
	parseValue := strings.TrimSpace(*record.ResourceRecords[0].Value)
	if !strings.Contains(parseValue, "://") {
		parseValue = "//" + parseValue
	}
	u, _ := url.Parse(parseValue)
	tmpExtractedResult.ResourceDNSName = strings.TrimRight(strings.ToLower(u.Host), ".")
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

// ebsDescribeEnvironmentsAPI is the subset of the Elastic Beanstalk client used
// to list environments, defined here so it can be mocked in tests.
type ebsDescribeEnvironmentsAPI interface {
	DescribeEnvironments(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error)
}

func listEBSEnvironment(ebsClient ebsDescribeEnvironmentsAPI, AWSResources map[string]bool) error {
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
