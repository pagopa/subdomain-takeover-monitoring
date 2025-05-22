#!/bin/bash
set -e

echo "🧹 Cleaning up DNS zone..."
RECORDS=$(aws route53 list-resource-record-sets \
  --hosted-zone-id $zone_id \
  --query "ResourceRecordSets[?Type!='NS' && Type!='SOA']" \
  --output json)

if [ "$(echo "$RECORDS" | jq length)" -gt 0 ]; then
  echo "📄 Found records to delete..."

  CHANGES=$(echo "$RECORDS" | jq 'map({Action: "DELETE", ResourceRecordSet: .})')
  echo "{\"Changes\": $CHANGES}" > delete-records.json

  aws route53 change-resource-record-sets \
    --hosted-zone-id $zone_id \
    --change-batch file://delete-records.json

  echo "✅ Custom records deleted."
else
  echo "ℹ️ No custom records found."
fi

aws route53 delete-hosted-zone --id $zone_id
echo "✅ DNS zone deleted correctly."