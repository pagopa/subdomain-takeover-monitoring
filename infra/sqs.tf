# Create an SQS Queue
resource "aws_sqs_queue" "account-ids" {
  name                       = "account-ids"
  visibility_timeout_seconds = 180
  message_retention_seconds  = 300
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.account_ids_deadletter_queue.arn
    maxReceiveCount     = 4
  })
  tags = {
    Name = "account-ids"
  }
}

resource "aws_iam_policy" "sqs_write_policy" {
  name        = "sqs-write-policy"
  description = "Allows writing to SQS queue"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage"
        ],
        Effect = "Allow",
        Resource = [
          aws_sqs_queue.account-ids.arn
        ]
      }
    ]
  })
}

resource "aws_sqs_queue" "account_ids_deadletter_queue" {
  name = "account-ids-deadletter-queue"
}

resource "aws_sqs_queue_redrive_allow_policy" "account_id_queue_redrive_allow_policy" {
  queue_url = aws_sqs_queue.account_ids_deadletter_queue.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue",
    sourceQueueArns   = [aws_sqs_queue.account-ids.arn]
  })
}