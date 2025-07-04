#!/bin/bash
set -e

echo "🔗 Creating S3 bucket..."
echo "$subdomain_and_s3_name"
aws s3api create-bucket --bucket $subdomain_and_s3_name --region $REGION --create-bucket-configuration LocationConstraint=$REGION
aws s3api put-public-access-block --bucket $subdomain_and_s3_name --public-access-block-configuration "{\"BlockPublicAcls\": false, \"IgnorePublicAcls\": false, \"BlockPublicPolicy\": false, \"RestrictPublicBuckets\": false}"
aws s3api put-bucket-ownership-controls --bucket $subdomain_and_s3_name --ownership-controls '{ "Rules": [ { "ObjectOwnership": "BucketOwnerPreferred" } ] }'
aws s3api put-bucket-acl --bucket $subdomain_and_s3_name --acl public-read-write
S3_FQDN="$subdomain_and_s3_name.s3.$REGION.amazonaws.com"
echo "bucket_url=https://$S3_FQDN" >> $GITHUB_ENV
echo "✅ S3 bucket created correctly."