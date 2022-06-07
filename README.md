## Apigateway REST API Lambda Authorizer Example with Third Party Identity Provider

This repo contains an example to use any third-part Identity provider with API Gateway Rest API. A very basic PetStore API with one method is added for demonstration. The below example can also be used with HTTP APIs as well.

## Pre-requisites

1.	Setup 'aws cli' 
2.	Install 'npm'
3.	Create an S3 bucket that will be used by CloudFormation package command to store local artifacts.

## Deployment steps

1. Clone the repo
2. cd src && npm install
3. Edit config to specify the details of the third-party provider.
4. run ./deploy.sh

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

