#!/bin/bash

set -e

action=$1
env=$2
shift 2
other=$@

# Check for missing action argument
if [ -z "$action" ]; then
  echo "Error: Missing action. Valid actions are: init, apply, plan, refresh, import, output, state, taint, destroy, console."
  exit 1
fi

# Check for missing environment argument and validate it
if [ -z "$env" ] || ! [[ "$env" =~ ^(dev|uat|prod)$ ]]; then
  echo "Error: Invalid environment. Valid environments are: dev, uat, or prod."
  exit 1
fi

# Validate the action
valid_actions="init plan apply refresh import output state taint destroy console"
if echo "$valid_actions" | grep -qw "$action"; then
  # Initialize Terraform backend
  terraform init -reconfigure -backend-config="./env/$env/backend.tfvars"

  # Handle specific actions
  case "$action" in
    output | state | taint)
      terraform $action $other
      ;;
    *)
      terraform $action -var-file="./env/$env/terraform.tfvars" $other
      ;;
  esac
else
  echo "Error: Invalid action '$action'. Allowed actions are: $valid_actions."
  exit 1
fi
