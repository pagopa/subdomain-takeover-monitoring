data "aws_caller_identity" "current" {}

resource "aws_iam_role" "github_health_check_role" {
  name        = "SubdomainTakeoverHealthCheckRole"
  description = "Role to perform healt check of subdomain takeover monitoring tool"


  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" : [
              "repo:${var.github_repository}:*"
            ]
          },
          "ForAllValues:StringEquals" = {
            "token.actions.githubusercontent.com:iss" : "https://token.actions.githubusercontent.com",
            "token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "subdomain_health_check_policy" {
  name        = "SubdomainHealtCheckPolicy"
  description = "Policy to perform healt check of subdomain takeover monitoring tool"

  policy = file(
    "./iam_policies/health-check-policy.json"
  )
}

resource "aws_iam_role_policy_attachment" "subdomain_health_check" {
  role       = aws_iam_role.github_health_check_role.name
  policy_arn = aws_iam_policy.subdomain_health_check_policy.id
}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}