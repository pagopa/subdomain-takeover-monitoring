# Subdomain Takeover Monitoring

## Project Overview

The **Subdomain Takeover Monitoring** project aims to detect and prevent potential subdomain takeovers, a critical security vulnerability where attackers exploit abandoned or misconfigured subdomains to gain unauthorized control. This vulnerability can lead to severe risks such as phishing attacks or unauthorized access. Effective DNS management and timely subdomain decommissioning are crucial to mitigate these security threats.

The repository is organized into two main parts:

- **cmd folder**: Contains Golang scripts used for Lambda functions.
  - `azure/`: Scripts for the Azure Lambda function.
  - `aws/`: Scripts for the AWS Lambda functions.

- **infra folder**: Includes Terraform scripts for setting up necessary infrastructure.

## Prerequisites

After cloning the repository, execute the following command:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./infra/tf_generated_azure/src/bootstrap ./cmd/azure/azure.go && cp ./assets/img/queries/query_azure ./infra/tf_generated_azure/src/query
```

## Components and Infrastructure
The **subdomain takeover monitoring** solution involves continuous monitoring of DNS records and identification of potential vulnerabilities in subdomains associated with Azure and AWS resources.

### Subdomain Takeover Monitoring - Azure implementation
Here there is the logic implementation of the tool which focuses on Azure resources:

![logicflow](./assets/img/logic-flow-azure.png)

### Subdomain Takeover Monitoring - AWS implementation
Here there is the logic implementation of the tool which focuses on AWS resources:

![logicflow](./assets/img/logic-flow-aws.png)


