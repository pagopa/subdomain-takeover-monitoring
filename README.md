# Subdomain Takeover Monitoring

## Project Overview

The **Subdomain Takeover Monitoring** project aims to detect and prevent potential subdomain takeovers, a critical security vulnerability where attackers exploit abandoned or misconfigured subdomains to gain unauthorized control. This vulnerability can lead to severe risks such as phishing attacks or unauthorized access. Effective DNS management and timely subdomain decommissioning are crucial to mitigate these security threats.

The repository is organized into two main parts:

- **cmd folder**: Contains Golang scripts used for Lambda functions.
  - `azure/`: Scripts for the Azure Lambda function.
  - `aws/`: Planned scripts for the AWS Lambda function (yet to be implemented).

- **infra folder**: Includes Terraform scripts for setting up necessary infrastructure.

## Prerequisites

After cloning the repository, execute the following command:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ./infra/tf_generated_azure/src/bootstrap ./cmd/azure/azure.go && cp ./assets/img/queries/query_azure ./infra/tf_generated_azure/src/query

## Components and Infrastructure

The current implementation focuses on Azure resources:

Here there is the logic flow of the implementation:

![logicflow](./assets/img/logic-flow.png)

The **subdomain takeover monitoring** solution involves continuous monitoring of DNS records and identification of potential vulnerabilities in subdomains associated with Azure resources.


_NOTE: The AWS part is planned but not yet implemented._

