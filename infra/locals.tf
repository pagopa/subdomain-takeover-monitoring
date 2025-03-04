locals {
  function_name      = "bootstrap"
  azure_src_path     = "${path.module}/../cmd/azure/azure.go"
  query_src_path     = "${path.module}/../assets/img/queries/query_azure"
  azure_binary_path  = "${path.module}/tf_generated_azure/src/${local.function_name}"
  azure_dir_path     = "${path.module}/tf_generated_azure/src/"
  query_binary_path  = "${path.module}/tf_generated_azure/src/query"
  azure_archive_path = "${path.module}/tf_generated_azure/v1/azure-script.zip"

  aws_list-lambda_src_path     = "${path.module}/../cmd/aws/list-lambda/list-lambda.go"
  aws_list-lambda_binary_path  = "${path.module}/tf_generated_aws_list-lambda/src/${local.function_name}"
  aws_list-lambda_dir_path     = "${path.module}/tf_generated_aws_list-lambda/src/"
  aws_list-lambda_archive_path = "${path.module}/tf_generated_aws_list-lambda/v1/list-lambda-script.zip"

  aws_verify-takeover_src_path     = "${path.module}/../cmd/aws/verify-takeover/verify-takeover.go"
  aws_verify-takeover_binary_path  = "${path.module}/tf_generated_aws_verify-takeover/src/${local.function_name}"
  aws_verify-takeover_dir_path     = "${path.module}/tf_generated_aws_verify-takeover/src/"
  aws_verify-takeover_archive_path = "${path.module}/tf_generated_aws_verify-takeover/v1/verify-takeover-script.zip"
}

