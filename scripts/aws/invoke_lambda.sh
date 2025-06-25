#!/bin/bash
set -e

echo "🔗 Invoking lambda of subdomain takeover monitoring tool for AWS..."
LAMBDA_NAME="aws_list-accounts-dev"
aws lambda invoke \
--function-name "$LAMBDA_NAME" \
--payload '{}' \
out.json > /dev/null 2>&1
echo "✅ Lambda invoked correctly."