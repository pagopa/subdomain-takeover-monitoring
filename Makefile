RELEASE_PATH = release
SOURCE_PATH = cmd
INFRA_PATH = infra

# Build configuration
OS = linux
AWS_ARCH = arm64
CGO_ENABLED = 0

# Component definitions
VERIFY_PATH = ${SOURCE_PATH}/aws/verify-takeover/verify-takeover.go
VERIFY_DIR = ${RELEASE_PATH}/verify-takeover
VERIFY_BINARY = ${VERIFY_DIR}/bootstrap
VERIFY_ZIP = ${INFRA_PATH}/tf_generated_aws_verify-takeover/v1/verify-takeover-script.zip

LIST_PATH = ${SOURCE_PATH}/aws/list-lambda/list-lambda.go
LIST_DIR = ${RELEASE_PATH}/list-lambda
LIST_BINARY = ${LIST_DIR}/bootstrap
LIST_ZIP = ${INFRA_PATH}/tf_generated_aws_list-lambda/v1/list-lambda-script.zip

# azure also bundles the query_azure asset alongside the binary
AZURE_PATH = ${SOURCE_PATH}/azure/azure.go
AZURE_DIR = ${RELEASE_PATH}/azure
AZURE_BINARY = ${AZURE_DIR}/bootstrap
AZURE_QUERY_SRC = assets/img/queries/query_azure
AZURE_QUERY = ${AZURE_DIR}/query
AZURE_ZIP = ${INFRA_PATH}/tf_generated_azure/v1/azure-script.zip

# Common build var
AWS_BUILD_ENV = GOOS=${OS} GOARCH=${AWS_ARCH} CGO_ENABLED=${CGO_ENABLED}

.PHONY: build build-verify-takeover build-list-lambda build-azure \
	clean clean-verify-takeover clean-list-lambda clean-azure

build: build-verify-takeover build-list-lambda build-azure

build-verify-takeover:
	rm -rf ${VERIFY_DIR}
	mkdir -p ${VERIFY_DIR} ${dir ${VERIFY_ZIP}}
	${AWS_BUILD_ENV} go build -o ${VERIFY_BINARY} ${VERIFY_PATH}
	rm -f ${VERIFY_ZIP}
	cd ${VERIFY_DIR} && zip -r -X ${abspath ${VERIFY_ZIP}} bootstrap

build-list-lambda:
	rm -rf ${LIST_DIR}
	mkdir -p ${LIST_DIR} ${dir ${LIST_ZIP}}
	${AWS_BUILD_ENV} go build -o ${LIST_BINARY} ${LIST_PATH}
	rm -f ${LIST_ZIP}
	cd ${LIST_DIR} && zip -r -X ${abspath ${LIST_ZIP}} bootstrap

build-azure:
	rm -rf ${AZURE_DIR}
	mkdir -p ${AZURE_DIR} ${dir ${AZURE_ZIP}}
	${AWS_BUILD_ENV} go build -o ${AZURE_BINARY} ${AZURE_PATH}
	cp ${AZURE_QUERY_SRC} ${AZURE_QUERY}
	rm -f ${AZURE_ZIP}
	cd ${AZURE_DIR} && zip -r -X ${abspath ${AZURE_ZIP}} bootstrap query

clean: clean-verify-takeover clean-list-lambda clean-azure

clean-verify-takeover:
	rm -rf ${VERIFY_DIR}
	rm -f ${VERIFY_ZIP}

clean-list-lambda:
	rm -rf ${LIST_DIR}
	rm -f ${LIST_ZIP}

clean-azure:
	rm -rf ${AZURE_DIR}
	rm -f ${AZURE_ZIP}
