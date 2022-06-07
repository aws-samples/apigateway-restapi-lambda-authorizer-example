#!/bin/bash
set -ux

# 1) CONFIG
# read the configuration file to load variables into this shell script
source config

# 2) Creating the package with artifacts uploaded to the s3 bucket
echo "Creating the package"
aws cloudformation package --template-file template.yaml \
        --s3-bucket $ARTIFACTS_BUCKET \
        --output-template-file infra-packaged.template

# 3) Validate the template
echo "Validating the output template"
aws cloudformation validate-template \
  --template-body file://infra-packaged.template

# 3) Deploying the template
echo "Deploying the output template"
aws cloudformation deploy \
    --template-file infra-packaged.template \
    --stack-name $STACK_NAME \
    --region $REGION \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        pArtifactsBucket=$ARTIFACTS_BUCKET \
        pTokenIssuer=$TOKEN_ISSUER_URI \
        pJWKSUri=$JWKS_URI \
        pAudience=$AUDIENCE \
         
echo "Updated/Created stack $STACK_NAME successfully"
