<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.2.0 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | 2.4.2 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.31.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | 2.4.2 |
| <a name="provider_null"></a> [null](#provider\_null) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_lambda_azure"></a> [lambda\_azure](#module\_lambda\_azure) | git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git | b88a85627c84a4e9d1ad2a655455d10b386bc63f |

## Resources

| Name | Type |
|------|------|
| [null_resource.azure_function_binary](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [archive_file.azure_function_archive](https://registry.terraform.io/providers/hashicorp/archive/2.4.2/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region (default is Milan) | `string` | `"eu-south-1"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_azure_binary_path"></a> [azure\_binary\_path](#output\_azure\_binary\_path) | n/a |
<!-- END_TF_DOCS -->