import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const templateUrl = new URL('../bootstrap-template.yaml', import.meta.url);
const template = await readFile(templateUrl, 'utf8');
const importTemplateUrl = new URL('../bootstrap-import-bucket-template.yaml', import.meta.url);
const importTemplate = await readFile(importTemplateUrl, 'utf8');

function resourceBlock(name, nextName) {
  const start = template.indexOf(`  ${name}:\n`);
  const end = nextName ? template.indexOf(`  ${nextName}:\n`, start + 1) : template.length;
  assert.notEqual(start, -1, `${name} must exist`);
  assert.notEqual(end, -1, `${nextName} must exist after ${name}`);
  return template.slice(start, end);
}

const bucket = resourceBlock('RingPrivateArtifactBucket', 'RingPrivateArtifactBucketPolicy');
const bucketPolicy = resourceBlock('RingPrivateArtifactBucketPolicy', 'RingPrivateCloudFormationExecutionRole');
const executionRole = resourceBlock('RingPrivateCloudFormationExecutionRole', 'RingPrivateLambdaRuntimeRole');
const runtimeRole = resourceBlock('RingPrivateLambdaRuntimeRole');

test('bootstrap has exactly the four admitted resources and no outputs or parameters', () => {
  const resources = [...template.matchAll(/^  ([A-Za-z0-9]+):\n    Type: ([^\n]+)$/gm)]
    .map(([, logicalId, type]) => ({ logicalId, type }));
  assert.deepEqual(resources, [
    { logicalId: 'RingPrivateArtifactBucket', type: 'AWS::S3::Bucket' },
    { logicalId: 'RingPrivateArtifactBucketPolicy', type: 'AWS::S3::BucketPolicy' },
    { logicalId: 'RingPrivateCloudFormationExecutionRole', type: 'AWS::IAM::Role' },
    { logicalId: 'RingPrivateLambdaRuntimeRole', type: 'AWS::IAM::Role' },
  ]);
  assert.doesNotMatch(template, /^Parameters:|^Outputs:/m);
  assert.equal((template.match(/DeletionPolicy: Retain/g) ?? []).length, 4);
  assert.equal((template.match(/UpdateReplacePolicy: Retain/g) ?? []).length, 4);
});

test('recovery import template contains only the exact retained bucket actual state', () => {
  const resources = [...importTemplate.matchAll(/^  ([A-Za-z0-9]+):\n    Type: ([^\n]+)$/gm)]
    .map(([, logicalId, type]) => ({ logicalId, type }));
  assert.deepEqual(resources, [
    { logicalId: 'RingPrivateArtifactBucket', type: 'AWS::S3::Bucket' },
  ]);
  assert.doesNotMatch(importTemplate, /AWS::S3::BucketPolicy|AWS::IAM::Role|^Parameters:|^Outputs:/m);
  const importBucketStart = importTemplate.indexOf('  RingPrivateArtifactBucket:\n');
  assert.notEqual(importBucketStart, -1);
  const importBucket = importTemplate.slice(importBucketStart);
  assert.match(importBucket, /BucketName: !Sub ring-home-mcp-private-artifacts-\$\{AWS::AccountId\}-\$\{AWS::Region\}/);
  assert.match(importBucket, /SSEAlgorithm: AES256/);
  assert.match(importBucket, /BlockedEncryptionTypes:\s*\n\s+EncryptionType:\s*\n\s+- SSE-C/);
  assert.match(importBucket, /BucketKeyEnabled: false/);
  for (const setting of ['BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets']) {
    assert.match(importBucket, new RegExp(`${setting}: true`));
  }
  assert.match(importBucket, /ObjectOwnership: BucketOwnerEnforced/);
  assert.doesNotMatch(importBucket, /VersioningConfiguration|LifecycleConfiguration/);
  assert.equal((importBucket.match(/- Key:/g) ?? []).length, 4);
});

test('artifact bucket is fixed, private, encrypted, versioned, retained and lifecycle bounded', () => {
  assert.match(bucket, /BucketName: !Sub ring-home-mcp-private-artifacts-\$\{AWS::AccountId\}-\$\{AWS::Region\}/);
  assert.match(bucket, /SSEAlgorithm: AES256/);
  assert.match(bucket, /BlockedEncryptionTypes:\s*\n\s+EncryptionType:\s*\n\s+- SSE-C/);
  assert.match(bucket, /VersioningConfiguration:\n        Status: Enabled/);
  for (const setting of ['BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets']) {
    assert.match(bucket, new RegExp(`${setting}: true`));
  }
  assert.match(bucket, /ObjectOwnership: BucketOwnerEnforced/);
  assert.match(bucket, /AbortIncompleteMultipartUpload:[\s\S]*DaysAfterInitiation: 7/);
  assert.match(bucket, /NoncurrentVersionExpiration:[\s\S]*NoncurrentDays: 30/);
  assert.doesNotMatch(bucket, /ExpirationInDays|ExpiredObjectDeleteMarker/);
});

test('artifact policy only denies plaintext transport for the bucket and its objects', () => {
  assert.match(bucketPolicy, /Sid: DenyInsecureTransport[\s\S]*Effect: Deny/);
  assert.match(bucketPolicy, /Principal: '\*'[\s\S]*Action: s3:\*/);
  assert.match(bucketPolicy, /aws:SecureTransport: 'false'/);
  assert.match(bucketPolicy, /!GetAtt RingPrivateArtifactBucket\.Arn/);
  assert.match(bucketPolicy, /!Sub \$\{RingPrivateArtifactBucket\.Arn\}\/\*/);
  assert.doesNotMatch(bucketPolicy, /Effect: Allow/);
});

test('fixed names, path and governance tags are exact', () => {
  assert.match(executionRole, /RoleName: ring-home-mcp-private-cfn-exec/);
  assert.match(runtimeRole, /RoleName: ring-home-mcp-private-lambda-runtime/);
  for (const role of [executionRole, runtimeRole]) {
    assert.match(role, /Path: \/ring-home-mcp-private\//);
  }
  for (const block of [bucket, executionRole, runtimeRole]) {
    assert.match(block, /Key: Project\n          Value: ring-home-mcp-hub/);
    assert.match(block, /Key: Boundary\n          Value: RingOnly/);
    assert.match(block, /Key: WorkOrder\n          Value: 20260929_ring_private_linking/);
    assert.match(block, /Key: ManagedBy\n          Value: CloudFormation/);
  }
});

test('role trusts are service-only and cannot be assumed by an account principal', () => {
  assert.match(executionRole, /Principal:\n              Service: cloudformation\.amazonaws\.com[\s\S]*Action: sts:AssumeRole/);
  assert.match(runtimeRole, /Principal:\n              Service: lambda\.amazonaws\.com[\s\S]*Action: sts:AssumeRole/);
  assert.doesNotMatch(executionRole + runtimeRole, /Principal:[\s\S]{0,100}(?:AWS:|Federated:)/);
});

test('execution role can manage only deterministic Ring resources and pass the exact runtime role', () => {
  const expectedFragments = [
    'function:ring-home-mcp-private',
    'log-group:/aws/lambda/ring-home-mcp-private',
    'table/ring-home-mcp-private-link',
    'alias/ring-home-mcp-private-token',
    'secret:ring-home-mcp-private/provider-*',
    'secret:ring-home-mcp-private/digest-*',
    'secret:ring-home-mcp-private/telegram-*',
    'Resource: !GetAtt RingPrivateLambdaRuntimeRole.Arn',
    'iam:PassedToService: lambda.amazonaws.com',
  ];
  for (const fragment of expectedFragments) assert.equal(executionRole.includes(fragment), true, fragment);
  assert.match(
    executionRole,
    /Sid: ReadRingPrivateDeploymentArtifacts[\s\S]*s3:GetObject[\s\S]*s3:GetObjectVersion[\s\S]*Resource: !Sub \$\{RingPrivateArtifactBucket\.Arn\}\/sam\/ring-home-mcp-private\/\*/,
  );
  assert.doesNotMatch(executionRole, /logs:DescribeLogGroups/);
  assert.match(executionRole, /kms:CreateKey[\s\S]*Resource: '\*'[\s\S]*aws:RequestTag\/Project: ring-home-mcp-hub/);
  assert.doesNotMatch(executionRole, /iam:(?:Create|Delete|Update|Put|Attach|Detach|Tag|Untag|Set)[A-Za-z]*/);
  assert.doesNotMatch(executionRole, /secretsmanager:GetSecretValue|secretsmanager:PutSecretValue/);
  assert.doesNotMatch(executionRole, /Action: '\*'|Action: \*/);
});

test('runtime role has only exact application data-plane actions and resources', () => {
  const actions = [...runtimeRole.matchAll(/^\s+- ([a-z0-9]+:[A-Za-z0-9*]+)$/gm)].map(match => match[1]);
  assert.deepEqual(actions.sort(), [
    'dynamodb:ConditionCheckItem',
    'dynamodb:GetItem',
    'dynamodb:GetItem',
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:PutItem',
    'dynamodb:TransactWriteItems',
    'dynamodb:UpdateItem',
    'dynamodb:UpdateItem',
    'dynamodb:Query',
    'dynamodb:TransactGetItems',
    'dynamodb:TransactWriteItems',
    'kms:Decrypt',
    'kms:GenerateDataKey',
    'logs:CreateLogStream',
    'logs:PutLogEvents',
  ].sort());
  assert.match(runtimeRole, /Action: secretsmanager:GetSecretValue/);
  assert.match(runtimeRole, /table\/ring-home-mcp-private-link\/index\/GSI1/);
  assert.match(runtimeRole, /kms:GenerateDataKey[\s\S]*Resource: !Sub arn:\$\{AWS::Partition\}:kms:\$\{AWS::Region\}:\$\{AWS::AccountId\}:key\/\*[\s\S]*kms:ResourceAliases: alias\/ring-home-mcp-private-token/);
  assert.doesNotMatch(runtimeRole, /Resource: '\*'|Resource: \*$/m);
  assert.doesNotMatch(runtimeRole, /iam:|lambda:|s3:|cloudformation:/);
  assert.match(runtimeRole, /ignore_checks:\n            - W3037/);
  assert.match(runtimeRole, /dynamodb:TransactGetItems/);
  assert.match(runtimeRole, /dynamodb:TransactWriteItems/);
});

test('template has no protected-project reference or public application surface', () => {
  for (const forbidden of [
    'other-stack-a',
    'other-stack-b',
    'other-stack-c',
    'AWS::ApiGateway',
    'AWS::ApiGatewayV2',
    'AWS::Lambda::Url',
    'AWS::IoT',
  ]) {
    assert.equal(template.includes(forbidden), false, forbidden);
  }
});
