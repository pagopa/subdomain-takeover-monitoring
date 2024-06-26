resource "null_resource" "azure_function_binary" {
  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-trimpath go build -mod=readonly -ldflags='-s -w' -o ${local.azure_binary_path} ${local.azure_src_path}"
  }
}

// zip the binary, as we can upload only zip files to AWS lambda
data "archive_file" "azure_function_archive" {
  depends_on  = [null_resource.azure_function_binary]
  type        = "zip"
  source_file = local.azure_binary_path
  output_path = local.azure_archive_path
}


module "lambda_azure" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=b88a85627c84a4e9d1ad2a655455d10b386bc63f"
  #version = "7.7.0"
  depends_on = [
    data.archive_file.azure_function_archive
  ]
  function_name           = "azure-lambda"
  description             = "Lambda function used for the azure subdomaintakeover script"
  runtime                 = "provided.al2023"
  architectures           = ["arm64"]
  handler                 = "bootstrap"
  create_package          = false
  local_existing_package  = data.archive_file.azure_function_archive.output_path
  ignore_source_code_hash = false

  publish = true



  environment_variables = {

  }


  memory_size = 128
  timeout     = 30

  logging_log_group                 = "/aws/lambda/azure-lambda"
  cloudwatch_logs_retention_in_days = 7

}












