 /*
 * Lambda Authorizer to validate authorization tokens from a third-party Identity Provider
 */
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const util = require('util');

//This checks for scopes and can be stored in Dynamodb or s3
const apiPermissions = [
  {
    "resource": "pets",
    "stage": "test", 
    "httpVerb": "GET",
    "scope": "openid,profile"
  }
  // Add more scopes as needed
];

// Fetch the Authorization token from the event params
const getAuthToken = (params) => {
  if (!params.type || params.type !== 'TOKEN') {
      throw new Error('"event.type" value must be "TOKEN"');
  }

  const token = params.authorizationToken;
  if (!token) {
      throw new Error('Expected "event.authorizationToken" parameter not set');
  }

  const match = token.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
      throw new Error(`Invalid Authorization token - ${token} does not match "Bearer .*"`);
  }
  return match[1];
}

const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  jwksUri: process.env.JWKS_URI
});

const jwtConfig = {
  issuer: process.env.TOKEN_ISSUER_URI,
  audience: process.env.AUDIENCE
};

// Generate an IAM policy for a a specific Principal Id
function generatePolicy(principalId, policyStatements) {
  'use strict';
  var authResponse = {};
  authResponse.principalId = principalId;
  var policyDocument = {};
  policyDocument.Version = '2012-10-17';
  policyDocument.Statement = policyStatements;
  authResponse.policyDocument = policyDocument;
  return authResponse;
};

// Generate an IAM policy statement for different API params
function generatePolicyStatement(apiName, apiStage, apiVerb, apiResource, action) {
  'use strict';
  var statement = {};
  statement.Action = 'execute-api:Invoke';
  statement.Effect = action;
  var methodArn = apiName + "/" + apiStage + "/" + apiVerb + "/" + apiResource;
  statement.Resource = methodArn;
  return statement;
};

// Generate an IAM policy statement for a Rest API Method ARN
function generatePolicyStatementForMethodArn(methodArn, action) {
  'use strict';
  var statement = {};
  statement.Action = 'execute-api:Invoke';
  statement.Effect = action;
  statement.Resource = methodArn;
  return statement;
};

// Verify access token from event params
function verifyAccessToken(params) {
  'use strict';
  //Get the passed Authentication token
  const token = getAuthToken(params);

  //Decode the token
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
      throw new Error('invalid token');
  }

  //Get the public signin key to verify the token with the provider
  const getSigningKey = util.promisify(client.getSigningKey);
  return getSigningKey(decoded.header.kid)
      .then((key) => {
          const signingKey = key.publicKey || key.rsaPublicKey;
          return jwt.verify(token, signingKey, jwtConfig);
      })
      .then((decoded));
};

function generateIAMPolicy (user, arn, scopeClaims) {
  'use strict';
  var policyStatements = [];
  
  // Iterate over API Permissions
  for ( var i = 0; i < apiPermissions.length; i++ ) {
  // Check if token scopes exist in API Permission
    var scopes = apiPermissions[i].scope.split(",");
    if ( scopeClaims.sort().join(',') ==  scopes.sort().join(',')) {
    // User token has appropriate scope, add API permission to policy statements
      policyStatements.push(generatePolicyStatementForMethodArn(arn, "Allow"));
    }
  }

  // If no policy statements are generated, create deny policy
  if (policyStatements.length === 0) {
    var policyStatement = generatePolicyStatement("*", "*", "*", "*", "Deny");
    policyStatements.push(policyStatement);
  }
  return generatePolicy(user, policyStatements);
};


exports.handler = async function(event, context) {  
  var iamPolicy = null;

  try {
    var token = await verifyAccessToken(event);
    var scopeClaims = [];
    scopeClaims.push(token.scopes || token.scp);
    iamPolicy = generateIAMPolicy(token.sub, event.methodArn, scopeClaims);
    console.log(JSON.stringify(iamPolicy));
  } 
  catch(err) {
    console.log(err);
    var policyStatements = [];
    var policyStatement = generatePolicyStatement("*", "*", "*", "*", "Deny");
    policyStatements.push(policyStatement);
    iamPolicy = generatePolicy('user', policyStatements);
  }
  return iamPolicy;
};  


