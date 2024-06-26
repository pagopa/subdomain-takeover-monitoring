locals {
  function_name      = "bootstrap"
  azure_src_path     = "${path.module}/../cmd/azure/main.go"
  azure_binary_path  = "${path.module}/tf_generated_azure/${local.function_name}"
  azure_archive_path = "${path.module}/tf_generated_azure/azure-script.zip"
}

output "azure_binary_path" {
  value = local.azure_binary_path
}