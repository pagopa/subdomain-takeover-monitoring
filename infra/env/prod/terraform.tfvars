tags = {
  "CreatedBy"   = "Terraform"
  "Environment" = "Prod"
  "Owner"       = "ProdSec"
  "Scope"       = "tfstate"
  "Source"      = "https://github.com/pagopa/subdomain-takeover-monitoring"
  "name"        = "S3 Remote Terraform State Store"
}

aws_region ="eu-west-1"
env = "prod"
s3_tf_state_bucket = "terraform-state-637423468901"