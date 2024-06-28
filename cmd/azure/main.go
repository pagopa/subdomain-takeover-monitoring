package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

type MyEvent struct {
	Name string `json:"name"`
}

func HandleRequest(ctx context.Context, event MyEvent) (string, error) {
	return fmt.Sprintf("Hello, %s!", event.Name), nil
}

func main() {
	lambda.Start(HandleRequest)
}
