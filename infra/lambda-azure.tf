resource "null_resource" "azure_function_binary" {
  triggers = {
    build_trigger = sha256(join("", [
      filesha256("${local.azure_src_path}"),
      filesha256("${path.module}/../internal/pkg/slack/slack.go")
    ]))
  }

  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ${local.azure_binary_path} ${local.azure_src_path} && cp ${local.query_src_path} ${local.query_binary_path} "
  }
}

// zip the binary, as we can upload only zip files to AWS lambda
data "archive_file" "azure_function_archive" {
  depends_on  = [null_resource.azure_function_binary]
  type        = "zip"
  source_dir  = local.azure_dir_path
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
data "aws_ssm_parameter" "slack_token" {
  name = "SLACK_TOKEN"
}
data "aws_ssm_parameter" "channel_id" {
  name = "CHANNEL_ID"
}
data "aws_ssm_parameter" "channel_id_debug" {
  name = "CHANNEL_ID_DEBUG"
}

module "lambda_azure" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=b88a85627c84a4e9d1ad2a655455d10b386bc63f"
  #version = "7.7.0"
  depends_on = [
    data.archive_file.azure_function_archive
  ]
  function_name           = "azure-lambda-${var.env}"
  description             = "Lambda function used for the azure subdomaintakeover script in ${var.env} environment"
  runtime                 = "provided.al2023"
  architectures           = ["arm64"]
  handler                 = "bootstrap"
  create_package          = false
  local_existing_package  = data.archive_file.azure_function_archive.output_path
  ignore_source_code_hash = false

  publish = true



  environment_variables = {
    SLACK_TOKEN         = data.aws_ssm_parameter.slack_token.value,
    CHANNEL_ID          = data.aws_ssm_parameter.channel_id.value,
    CHANNEL_ID_DEBUG    = data.aws_ssm_parameter.channel_id_debug.value,
    AZURE_TENANT_ID     = data.aws_ssm_parameter.azure_tenant_id.value,
    AZURE_CLIENT_ID     = data.aws_ssm_parameter.azure_client_id.value,
    AZURE_CLIENT_SECRET = data.aws_ssm_parameter.azure_client_secret.value
  }


  memory_size = 128
  timeout     = 900

  logging_log_group                 = "/aws/lambda/azure-lambda-${var.env}"
  cloudwatch_logs_retention_in_days = 7


  allowed_triggers = {
    ScheduleRule = {
      principal  = "events.amazonaws.com"
      source_arn = aws_cloudwatch_event_rule.schedule_azure.arn
    }
  }

  tags = var.tags

}


resource "aws_cloudwatch_event_rule" "schedule_azure" {
  name                = "Monday-schedule-${var.env}"
  description         = "Schedule a run for every monday"
  schedule_expression = "cron(0 9 ? * MON *)"
  state               = var.env == "prod" ? "ENABLED" : "DISABLED"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "schedule_lambda_function" {
  rule = aws_cloudwatch_event_rule.schedule_azure.name
  arn  = module.lambda_azure.lambda_function_arn
}






