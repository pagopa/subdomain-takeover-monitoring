#!/usr/bin/env bash
export AWS_PROFILE=$1
REGION="eu-south-1"
RANDOM_STRING=$(date +%s)
S3_BUCKET_NAME="terraform-state-${RANDOM_STRING}"
DYNAMO_TABLE_NAME="terraform-lock"

if [ -z "${AWS_PROFILE}" ]; then
    printf "\e[1;31mYou must provide a profile as first argument.\n"
    exit 1
fi

if [[ $(aws s3api list-buckets --region "${REGION}" --query "Buckets[].[Name]" --output text) = *"terraform-state"* ]]; then
   S3_BUCKET_NAME=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `terraform-state`) == `true`].[Name][0][0]')
   echo "[INFO] s3 bucket: ${S3_BUCKET_NAME=} already exists."     
else
   aws s3api create-bucket --bucket "${S3_BUCKET_NAME}" --acl  "private" --create-bucket-configuration LocationConstraint="${REGION}"
   aws s3api put-bucket-versioning --bucket "${S3_BUCKET_NAME}" --versioning-configuration Status=Enabled    
fi

if [[ $(aws dynamodb list-tables --region "${REGION}" --query "TableNames[]") == *"${DYNAMO_TABLE_NAME}"*  ]]; then
 echo "[INFO] DynamoDB table named ${DYNAMO_TABLE_NAME} already created."
 
else
 aws dynamodb create-table \
    --table-name "${DYNAMO_TABLE_NAME}" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5   
fi

echo "[INFO] S3_BUCKET_NAME: ${S3_BUCKET_NAME}"
echo "[INFO] DYNAMO_TABLE_NAME: ${DYNAMO_TABLE_NAME}"