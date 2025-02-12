package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	//"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	region = "eu-south-1"
)

func HandleRequest(ctx context.Context, event interface{}) (string, error) {
	//Assume il ruolo per listare gli account
	//Scarica la lista di account
	accounts, err := listAwsOrganizationAccounts(ctx)
	if err != nil {
		return "", err
	}
	//TODO: eliminare da result gli account per cui non si vuole fare takeover
	//Scrivere result su una coda SQS
	sqsQueue := os.Getenv("SQS_LIST_ACCOUNTS")
	err = writeAccountsToSQS(accounts, sqsQueue, ctx)
	if err != nil {
		return "", err
	}
	return "Hello world", nil
}

func main() {
	lambda.Start(HandleRequest)
}

func listAwsOrganizationAccounts(ctx context.Context) ([]types.Account, error) {
	client := organizations.New(organizations.Options{Region: region})
	input := &organizations.ListAccountsInput{}
	result, err := client.ListAccounts(ctx, input)

	if err != nil {
		return nil, fmt.Errorf("errore nell'eleborare la lista: %v", err)
	}
	nextToken := result.NextToken
	for nextToken != nil {
		input2 := &organizations.ListAccountsInput{NextToken: nextToken}
		result2, err := client.ListAccounts(ctx, input2)
		if err != nil {
			return nil, err
		}
		result.Accounts = append(result.Accounts, result2.Accounts...)
		nextToken = result2.NextToken
	}
	return result.Accounts, nil
}

func writeAccountsToSQS(accounts []types.Account, sqsUrl string, ctx context.Context) error {
	client := sqs.New(sqs.Options{Region: region})
	for _, account := range accounts {
		jsonAccount, err := json.Marshal(account)
		jsonAccountString := string(jsonAccount)
		if err != nil {
			return err
		}
		_, err = client.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: &sqsUrl, MessageBody: &jsonAccountString})
		if err != nil {
			return err
		}
	}
	return nil
}
