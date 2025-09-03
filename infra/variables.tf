# Input variable definitions

variable "aws_region" {
  type        = string
  description = "AWS region (default is Milan)"
}


variable "tags" {
  type = map(any)
}

variable "github_repository" {
  type        = string
  description = "Subdomain takeover monitoring github repository"
  default     = "pagopa/subdomain-takeover-monitoring"
}

variable "env" {
  type = string
}

variable "s3_tf_state_bucket" {
  type        = string
  description = "Bucket S3 containing tf-state"
}