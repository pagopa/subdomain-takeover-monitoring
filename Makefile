FUNCTION_NAME = bootstrap
SOURCE_PATH = cmd
RELEASE_PATH = release

AWS_LIST_ACCOUNTS_PATH = ${SOURCE_PATH}/aws/list-lambda/list-lambda.go
AWS_LIST_ACCOUNTS_BINARY_NAME = infra/tf_generated_aws_list-lambda/src/${FUNCTION_NAME}
AWS_LIST-LAMBDA_ARCHIVE_PATH = infra/tf_generated_aws_list-lambda/v1/list-lambda-script.zip

AWS_VERIFY_TAKEOVER_PATH = ${SOURCE_PATH}/aws/verify-takeover/verify-takeover.go
AWS_VERIFY_TAKEOVER_BINARY_NAME = infra/tf_generated_aws_verify-takeover/src/${FUNCTION_NAME}
AWS_VERIFY-TAKEOVER_ARCHIVE_PATH = infra/tf_generated_aws_verify-takeover/v1/verify-takeover-script.zip

AZURE_LAMBDA_PATH = ${SOURCE_PATH}/azure/azure.go
AZURE_LAMBDA_BINARY_NAME = infra/tf_generated_azure/src/${FUNCTION_NAME}
AZURE_ARCHIVE_PATH = infra/tf_generated_azure/v1/azure-script.zip

TAGS = lambda.norpc
OS = linux
AWS_ARCH = arm64
ACTION_ARCH = amd64
CGO_ENABLED = 0

build-all: clean-all build-aws-list-accounts build-aws-verify-takeover build-azure-lambda

build-aws-list-accounts: 
	GOOS=${OS} GOARCH=${AWS_ARCH} CGO_ENABLED=${CGO_ENABLED} go build -o ${AWS_LIST_ACCOUNTS_BINARY_NAME} -tags ${TAGS} ${AWS_LIST_ACCOUNTS_PATH}
	zip ./${AWS_LIST-LAMBDA_ARCHIVE_PATH} ./${AWS_LIST_ACCOUNTS_BINARY_NAME}
clean-aws-list-account:
	go clean
	rm -f ${AWS_LIST_ACCOUNTS_BINARY_NAME}

build-aws-verify-takeover: 
	GOOS=${OS} GOARCH=${AWS_ARCH} CGO_ENABLED=${CGO_ENABLED} go build -o ${AWS_VERIFY_TAKEOVER_BINARY_NAME} -tags ${TAGS} ${AWS_VERIFY_TAKEOVER_PATH}
	zip ./${AWS_VERIFY-TAKEOVER_ARCHIVE_PATH} ./${AWS_VERIFY_TAKEOVER_BINARY_NAME}
clean-aws-verify-takeover:
	go clean
	rm -f ${AWS_VERIFY_TAKEOVER_BINARY_NAME}

build-azure-lambda: 
	GOOS=${OS} GOARCH=${AWS_ARCH} CGO_ENABLED=${CGO_ENABLED} go build -o ${AZURE_LAMBDA_BINARY_NAME} -tags ${TAGS} ${AZURE_LAMBDA_PATH} && cp ./assets/img/queries/query_azure ./infra/tf_generated_azure/src/query
	zip ./${AZURE_ARCHIVE_PATH} ./${AZURE_LAMBDA_BINARY_NAME}
clean-azure-lambda:
	go clean
	rm -f ${AZURE_LAMBDA_BINARY_NAME}

clean-all: clean-aws-list-account clean-aws-verify-takeover clean-azure-lambda

test:
	go vet ./...
	go test -v ./...