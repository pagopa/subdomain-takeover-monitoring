# Subdomain Takeover Monitoring
 
## Project Overview

The **Subdomain Takeover Monitoring** to detect and prevent potential subdomain takeover, a critical security vulnerability where attackers exploit abandoned or misconfigured subdomains. This vulnerability can cause serious risks, such as phishing attacks or data theft. Effective DNS management and timely deactivation of subdomains are critical to mitigating these threats.

The repository is organized into two main parts:

- **cmd folder**: Contains Golang scripts used for Lambda functions.
  - `azure/`: Scripts for the Azure Lambda function.
  - `aws/`: Scripts for the AWS Lambda functions.

- **infra folder**: Includes Terraform scripts for setting up necessary infrastructure.

## Prerequisites

After cloning the repository, execute the following commands:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./infra/tf_generated_azure/src/bootstrap ./cmd/azure/azure.go && cp ./assets/img/queries/query_azure ./infra/tf_generated_azure/src/query
```
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./infra/tf_generated_aws_list-lambda/src/bootstrap ./cmd/aws/list-lambda/list-lambda.go
```
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./infra/tf_generated_aws_verify-takeover/src/bootstrap ./cmd/aws/verify-takeover/verify-takeover.go
```

## Components and Infrastructure
The **subdomain takeover monitoring** solution involves continuous monitoring of DNS records and identification of potential vulnerabilities in subdomains associated with Azure and AWS resources.

### Subdomain Takeover Monitoring - Azure implementation
Here there is the logic implementation of the tool which focuses on Azure resources:

![logicflow](./assets/img/logic-flow-azure.png)

### Subdomain Takeover Monitoring - AWS implementation
Here there is the logic implementation of the tool which focuses on AWS resources:

![logicflow](./assets/img/logic-flow-aws.png)


