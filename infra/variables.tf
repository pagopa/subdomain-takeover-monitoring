# Input variable definitions

variable "aws_region" {
  type        = string
  description = "AWS region (default is Milan)"
  default     = "eu-south-1"
}


variable "tags" {
  type = map(any)
  default = {
    "CreatedBy" : "Terraform",
    "Environment" : "Dev"
  }
}

variable "github_repository" {
  type        = string
  description = "This github repository"
  default     = "pagopa/subdomain-takeover-monitoring"
}