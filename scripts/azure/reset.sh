#!/bin/bash
set -e


if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI not found. Install it before continuing."
    exit 1
fi

echo "Verifying Azure authentication..."
if ! az account show &> /dev/null; then
    echo "ERROR: Not authenticated in Azure. Run 'az login' before continuing."
    exit 1
fi



echo "Deleting Resource Group"
az group delete --name "$RESOURCE_GROUP" --yes


