resource "null_resource" "list-lambda_binary" {
  triggers = {
    build_trigger = "${md5(file(local.aws_list-lambda_src_path))}"
  }
  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ${local.aws_list-lambda_binary_path} ${local.aws_list-lambda_src_path}"
  }
}

// zip the binary, as we can upload only zip files to AWS lambda
data "archive_file" "aws_list-lambda_function_archive" {
  depends_on  = [null_resource.list-lambda_binary]
  type        = "zip"
  source_dir  = local.aws_list-lambda_dir_path
  output_path = local.aws_list-lambda_archive_path
}

module "lambda_aws_list-accounts" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=b88a85627c84a4e9d1ad2a655455d10b386bc63f"
  #version = "7.7.0"
  depends_on = [
    data.archive_file.aws_list-lambda_function_archive
  ]
  function_name           = "aws_list-accounts"
  description             = "Lambda function used to list account of AWS organization"
  runtime                 = "provided.al2023"
  architectures           = ["arm64"]
  handler                 = "bootstrap"
  create_package          = false
  local_existing_package  = data.archive_file.aws_list-lambda_function_archive.output_path
  ignore_source_code_hash = false

  publish = true

  memory_size = 128
  timeout     = 900

  logging_log_group                 = "/aws/lambda/aws_list-lambda"
  cloudwatch_logs_retention_in_days = 7


  allowed_triggers = {
    ScheduleRule = {
      principal = "events.amazonaws.com"
    }
  }

  environment_variables = {
    SQS_LIST_ACCOUNTS = data.aws_ssm_parameter.sqs_list_accounts.value
  }
}

data "aws_ssm_parameter" "sqs_list_accounts" {
  name = "SQS_LIST_ACCOUNTS"
}

//TODO: creare ruolo per la lambda con permessi di write su SQS