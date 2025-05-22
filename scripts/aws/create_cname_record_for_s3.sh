#!/bin/bash
set -e

echo "🔗 Creating CNAME record for S3..."
aws route53 change-resource-record-sets \
  --hosted-zone-id $zone_id \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "'$subdomain_and_s3_name'",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{ "Value": "'$bucket_url'" }]
      }
    }]
  }'
echo "✅ CNAME recordo for S3 created correctly."