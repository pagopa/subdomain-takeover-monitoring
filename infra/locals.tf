locals {
  function_name      = "bootstrap"
  azure_src_path     = "${path.module}/../cmd/azure/azure.go"
  query_src_path     = "${path.module}/../cmd/azure/query"
  azure_binary_path  = "${path.module}/tf_generated_azure/src/${local.function_name}"
  azure_dir_path     = "${path.module}/tf_generated_azure/src/"
  query_binary_path  = "${path.module}/tf_generated_azure/src/query"
  azure_archive_path = "${path.module}/tf_generated_azure/v1/azure-script.zip"
}

