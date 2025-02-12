package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	//Scarica la lista di account
	accounts, err := listAwsOrganizationAccounts()
	if err != nil {
		return "", err
	}
	//TODO: eliminare da result gli account per cui non si vuole fare takeover
	//Scrivere result su una coda SQS
	sqsQueue := os.Getenv("SQS_LIST_ACCOUNTS")
	debugString, _ := json.Marshal(accounts)
	slog.Debug("HERE")
	slog.Debug(string(debugString))
	err = writeAccountsToSQS(accounts, sqsQueue)
	if err != nil {
		return "", err
	}
	return "Hello world", nil
}

func main() {
	lambda.Start(HandleRequest)
}

func assumeCrossRole() (*organizations.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("errore nel creare la configurazione: %v", err)
	}
	stsClient := *sts.NewFromConfig(cfg)
	roleArn := os.Getenv("LIST_ACCOUNTS_ROLE")
	roleSessionName := os.Getenv("LIST_ACCOUNTS_ROLE_SESSION_NAME")
	assumeRoleOutput, err := stsClient.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(900)})
	if err != nil {
		return nil, fmt.Errorf("errore nell'assunzione del ruolo: %v", err)
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
	client, err := assumeCrossRole()
	if err != nil {
		return nil, err
	}
	input := &organizations.ListAccountsInput{}
	result, err := client.ListAccounts(context.TODO(), input)

	if err != nil {
		return nil, fmt.Errorf("errore nell'eleborare la lista: %v", err)
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
	return result.Accounts, nil
}

func writeAccountsToSQS(accounts []types.Account, sqsUrl string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("errore nel creare la configurazione: %v", err)
	}
	client := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.Region = region })
	for _, account := range accounts {
		jsonAccount, err := json.Marshal(account)
		jsonAccountString := string(jsonAccount)
		if err != nil {
			return err
		}
		_, err = client.SendMessage(context.TODO(), &sqs.SendMessageInput{QueueUrl: &sqsUrl, MessageBody: &jsonAccountString})
		if err != nil {
			return err
		}
	}
	return nil
}

//Esempio di elemento nella coda {"Arn":"arn:aws:organizations::519902559805:account/o-c0e8t6lmm6/590183909663","Email":"interop-extra+dev@pagopa.it","Id":"590183909663","JoinedMethod":"CREATED","JoinedTimestamp":"2024-07-02T14:14:07.096Z","Name":"interop-extra-dev","Status":"ACTIVE"}
