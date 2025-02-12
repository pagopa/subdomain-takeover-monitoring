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
    LIST_ACCOUNTS_ROLE = data.aws_ssm_parameter.list_accounts_role.value
    LIST_ACCOUNTS_ROLE_SESSION_NAME = data.aws_ssm_parameter.list_accounts_role_session_name.value
  }
}

data "aws_ssm_parameter" "sqs_list_accounts" {
  name = "SQS_LIST_ACCOUNTS"
}

data "aws_ssm_parameter" "list_accounts_role" {
  name = "LIST_ACCOUNTS_ROLE"
}

data "aws_ssm_parameter" "list_accounts_role_session_name" {
  name = "LIST_ACCOUNTS_ROLE_SESSION_NAME"
}

resource "aws_iam_role_policy_attachment" "attach-sqs-policy" {
  role       = module.lambda_aws_list-accounts.lambda_role_name
  policy_arn = aws_iam_policy.sqs_write_policy.arn
}

resource "aws_iam_policy" "cross_account_role_policy" {
  name        = "cross-account-role-policy"
  description = "Allows lambda function to assume cross-account role"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::519902559805:role/CrossAccountSubdomainTakeOverLambda"
        }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach-cross-account-role-policy" {
  role       = module.lambda_aws_list-accounts.lambda_role_name
  policy_arn = aws_iam_policy.cross_account_role_policy.arn
}