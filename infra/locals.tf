locals {
  function_name      = "bootstrap"
  azure_src_path     = "${path.module}/../cmd/azure/azure.go"
  azure_binary_path  = "${path.module}/tf_generated_azure/${local.function_name}"
  azure_archive_path = "${path.module}/tf_generated_azure/v1/azure-script.zip"
}

