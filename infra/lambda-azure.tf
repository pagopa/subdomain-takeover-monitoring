resource "null_resource" "azure_function_binary" {
  triggers = {
    always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ${local.azure_binary_path} ${local.azure_src_path}&& cp ${local.query_src_path} ${local.query_binary_path} "
  }
}

// zip the binary, as we can upload only zip files to AWS lambda
data "archive_file" "azure_function_archive" {
  depends_on  = [null_resource.azure_function_binary]
  type        = "zip"
  source_dir = local.azure_dir_path
  output_path = local.azure_archive_path
}

data "aws_ssm_parameter" "azure_tenant_id" {
  name = "AZURE_TENANT_ID"
}
data "aws_ssm_parameter" "azure_client_id" {
  name = "AZURE_CLIENT_ID"
}

data "aws_ssm_parameter" "azure_client_secret" {
  name = "AZURE_CLIENT_SECRET"
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
    AZURE_TENANT_ID     = data.aws_ssm_parameter.azure_tenant_id.value,
    AZURE_CLIENT_ID     = data.aws_ssm_parameter.azure_client_id.value,
    AZURE_CLIENT_SECRET = data.aws_ssm_parameter.azure_client_secret.value
  }


  memory_size = 128
  timeout     = 30

  logging_log_group                 = "/aws/lambda/azure-lambda"
  cloudwatch_logs_retention_in_days = 7

}












