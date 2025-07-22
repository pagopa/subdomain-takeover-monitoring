#!/bin/bash
set -e



TIMESTAMP=$(date +%s)
RANDOM_SUFFIX=$(shuf -i 1000-9999 -n 1)



RESOURCE_GROUP="demo-rg-subdomain"
LOCATION="italynorth"
STORAGE_ACCOUNT_PREFIX="mystorage"
DNS_ZONE_NAME="example-${RANDOM_SUFFIX}.com"
RECORD_NAME="www"
TTL="300"

STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_PREFIX}${TIMESTAMP}${RANDOM_SUFFIX}"
STORAGE_ACCOUNT_NAME=$(echo "$STORAGE_ACCOUNT_NAME" | tr '[:upper:]' '[:lower:]' | head -c 24)


if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI not found. Install it before continuing."
    exit 1
fi

echo "Verifying Azure authentication"
if ! az account show &> /dev/null; then
    echo "ERROR: Not authenticated in Azure. Run 'az login' before continuing."
    exit 1
fi



echo "Creating Resource Group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "Resource Group '$RESOURCE_GROUP' created/verified"
echo "RESOURCE_GROUP=$RESOURCE_GROUP" >> $GITHUB_ENV

echo "Creating Storage Account"
az storage account create \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --access-tier Hot \
    --output none

echo "Storage Account created"


STORAGE_ENDPOINT="${STORAGE_ACCOUNT_NAME}.blob.core.windows.net"


echo "Creating DNS Zone"
if az network dns zone show --resource-group "$RESOURCE_GROUP" --name "$DNS_ZONE_NAME" &> /dev/null; then
    echo "WARNING: DNS Zone '$DNS_ZONE_NAME' already exists"
else
    az network dns zone create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$DNS_ZONE_NAME" \
        --output none
    echo "DNS Zone '$DNS_ZONE_NAME' created"
fi


echo "Creating CNAME record"
az network dns record-set cname set-record \
    --resource-group "$RESOURCE_GROUP" \
    --zone-name "$DNS_ZONE_NAME" \
    --record-set-name "$RECORD_NAME" \
    --cname "$STORAGE_ENDPOINT" \
    --ttl "$TTL" \
    --output none

echo "CNAME created"


echo "Verifying CNAME record:"
az network dns record-set cname show \
    --name "$RECORD_NAME" \
    --zone-name "$DNS_ZONE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "{Name:name, TTL:ttl, CNAME:cnameRecord.cname}" \
    --output none



echo "Waiting 3 minutes before deleting storage account..."
sleep 3m


echo "Deleting Storage Account to create dangling CNAME..."
az storage account delete \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --yes \
    --output none

echo "Waiting 3 minutes before deleting storage account..."
sleep 3m
