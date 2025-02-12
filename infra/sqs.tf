# Create an SQS Queue
resource "aws_sqs_queue" "account-ids" {
  name = "account-ids"

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
        ],
        Effect = "Allow",
        Resource = [
          aws_sqs_queue.account-ids.arn
        ]
      }
    ]
  })
}