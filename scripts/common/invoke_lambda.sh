#!/bin/bash
set -e

echo "🔗 Invoking lambda of subdomain takeover monitoring tool"
LAMBDA_NAME="$LAMBDA-$DEPLOY_ENV"
aws lambda invoke \
--function-name "$LAMBDA_NAME" \
--invocation-type Event \
--payload '{}' \
out.json > /dev/null 2>&1
echo "✅ Lambda invoked correctly."
echo "Waiting for 5 minutes..."
sleep 5m