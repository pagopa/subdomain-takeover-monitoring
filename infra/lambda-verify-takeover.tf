resource "null_resource" "verify-takeover_binary" {
  triggers = {
    build_trigger = "${md5(file(local.aws_verify-takeover_src_path))}"
  }
  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ${local.aws_verify-takeover_binary_path} ${local.aws_verify-takeover_src_path}"
  }
}

// zip the binary, as we can upload only zip files to AWS lambda
data "archive_file" "aws_verify-takeover_function_archive" {
  depends_on  = [null_resource.verify-takeover_binary]
  type        = "zip"
  source_dir  = local.aws_verify-takeover_dir_path
  output_path = local.aws_verify-takeover_archive_path
}

module "lambda_aws_verify-takeover" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=b88a85627c84a4e9d1ad2a655455d10b386bc63f"
  #version = "7.7.0"
  depends_on = [
    data.archive_file.aws_verify-takeover_function_archive
  ]
  function_name           = "aws_verify-takeover"
  description             = "Lambda function used to verify subdomain takeover into AWS accounts of organization"
  runtime                 = "provided.al2023"
  architectures           = ["arm64"]
  handler                 = "bootstrap"
  create_package          = false
  local_existing_package  = data.archive_file.aws_verify-takeover_function_archive.output_path
  ignore_source_code_hash = false

  publish = true

  memory_size = 128
  timeout     = 180

  logging_log_group                 = "/aws/lambda/aws_verify-takeover"
  cloudwatch_logs_retention_in_days = 7


  allowed_triggers = {
    ScheduleRule = {
      principal = "events.amazonaws.com"
    }
  }

  //Varibale already defined in lambda-list-accounts.tf and lambda-azure.tf
  environment_variables = {
    SLACK_TOKEN                     = data.aws_ssm_parameter.slack_token.value,
    CHANNEL_ID                      = data.aws_ssm_parameter.channel_id.value,
    CHANNEL_ID_DEBUG                = data.aws_ssm_parameter.channel_id_debug.value,
    SQS_LIST_ACCOUNTS               = data.aws_ssm_parameter.sqs_list_accounts.value
    PRODSEC_READONLY_ROLE           = data.aws_ssm_parameter.prodsec_read_only_role.value
    LIST_ACCOUNTS_ROLE_SESSION_NAME = data.aws_ssm_parameter.list_accounts_role_session_name.value
  }
}

resource "aws_iam_role_policy_attachment" "attach-sqs-policy-verify-takeover" {
  role       = module.lambda_aws_verify-takeover.lambda_role_name
  policy_arn = aws_iam_policy.sqs_write_policy.arn
}

resource "aws_lambda_event_source_mapping" "sqs_event_source" {
  event_source_arn = aws_sqs_queue.account-ids.arn
  function_name    = module.lambda_aws_verify-takeover.lambda_function_name
  batch_size       = 10
}

data "aws_ssm_parameter" "prodsec_read_only_role" {
  name = "PRODSEC_READONLY_ROLE"
}

resource "aws_iam_policy" "prodsec_cross_account_policy" {
  name        = "ProdSecCrossAccountPolicy"
  description = "Allows sts assume role"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "sts:AssumeRole"
        ],
        Effect = "Allow",
        Resource = [
          "arn:aws:iam::*:role/ProdsecRoleLambdaVerifyTakeover"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach-prodsec-cross-account-verify-takeover" {
  role       = module.lambda_aws_verify-takeover.lambda_role_name
  policy_arn = aws_iam_policy.prodsec_cross_account_policy.arn
}