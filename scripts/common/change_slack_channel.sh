#!/bin/bash
set -e

echo "🔗 Changing slack channel id"
LAMBDA_NAME="$LAMBDA-$DEPLOY_ENV"
CURRENT_ENV=$(aws lambda get-function-configuration --function-name "$LAMBDA_NAME" --query 'Environment.Variables' --output json)
ENV_KEY="CHANNEL_ID"
UPDATED_ENV=$(echo "$CURRENT_ENV" | jq --arg key "$ENV_KEY" --arg value "$ENV_VALUE" '.[$key] = $value')
FINAL_ENV=$(jq -n --argjson vars "$UPDATED_ENV" '{Variables: $vars}')
echo "$FINAL_ENV" > env.json
aws lambda update-function-configuration \
  --function-name $LAMBDA_NAME \
  --environment file://env.json > /dev/null 2>&1
echo "✅ Slack channel changed correctly." 
echo "Waiting 3 minutes"
sleep 3m