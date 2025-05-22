#!/bin/bash
set -e

echo "🧹 Deleting S3 bucket..."
aws s3 rm "s3://$subdomain_and_s3_name" --recursive || true
aws s3api delete-bucket --bucket $subdomain_and_s3_name
echo "✅ S3 bucket deleted correctly." 