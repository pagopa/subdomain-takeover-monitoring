# STACKSET creation on CloudFormation AWS

```
aws cloudformation create-stack-set \
    --stack-set-name  prodsec-role-lambda-verify-takeover \
    --template-body file://stackset-role.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --permission-mode SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --region eu-west-1
```
```
aws cloudformation create-stack-instances \
    --stack-set-name prodsec-role-lambda-verify-takeover \
    --deployment-targets OrganizationalUnitIds=ou-o5rt-5s7xpol0 \
    --regions eu-west-1 \
    --operation-preferences FailureToleranceCount=4,MaxConcurrentCount=5
```