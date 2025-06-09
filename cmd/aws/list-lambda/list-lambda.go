package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	//"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	region = "eu-south-1"
)

func HandleRequest(ctx context.Context, event interface{}) (string, error) {
	//Download list of accounts belonging to PagoPA org
	accounts, err := listAwsOrganizationAccounts()
	if err != nil {
		return "", err
	}
	//TODO: Write a file containing the account-ids not to be monitored and remove them from the downloaded list
	sqsQueue := os.Getenv("SQS_LIST_ACCOUNTS")
	err = writeAccountsToSQS(accounts, sqsQueue)
	if err != nil {
		return "", err
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

func assumeCrossRole() (*organizations.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	stsClient := *sts.NewFromConfig(cfg)
	roleArn := os.Getenv("LIST_ACCOUNTS_ROLE")
	roleSessionName := os.Getenv("LIST_ACCOUNTS_ROLE_SESSION_NAME")
	assumeRoleOutput, err := stsClient.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(900)})
	if err != nil {
		return nil, err
	}
	organizationsClient := organizations.NewFromConfig(cfg, func(o *organizations.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			*assumeRoleOutput.Credentials.AccessKeyId,
			*assumeRoleOutput.Credentials.SecretAccessKey,
			*assumeRoleOutput.Credentials.SessionToken,
		)
	})
	return organizationsClient, nil
}

func listAwsOrganizationAccounts() ([]types.Account, error) {
	slog.Info("Starting the listing account")
	client, err := assumeCrossRole()
	if err != nil {
		return nil, err
	}
	input := &organizations.ListAccountsInput{}
	result, err := client.ListAccounts(context.TODO(), input)

	if err != nil {
		return nil, err
	}
	nextToken := result.NextToken
	for nextToken != nil {
		input2 := &organizations.ListAccountsInput{NextToken: nextToken}
		result2, err := client.ListAccounts(context.TODO(), input2)
		if err != nil {
			return nil, err
		}
		result.Accounts = append(result.Accounts, result2.Accounts...)
		nextToken = result2.NextToken
	}
	slog.Info("listing account completed")
	return result.Accounts, nil
}

func writeAccountsToSQS(accounts []types.Account, sqsUrl string) error {
	slog.Info("Writing accounts to the SQS")
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return err
	}
	client := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.Region = region })
	jsonAccounts, err := json.Marshal(accounts)
	if err != nil {
		return err
	}
	jsonAccountString := string(jsonAccounts)
	_, err = client.SendMessage(context.TODO(), &sqs.SendMessageInput{QueueUrl: &sqsUrl, MessageBody: &jsonAccountString})
	if err != nil {
		return err
	}
	slog.Info("Writing to the SQS completed")
	return nil
}
