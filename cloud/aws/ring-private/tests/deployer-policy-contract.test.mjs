import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const base = new URL('../policies/', import.meta.url);
const b0 = JSON.parse(await readFile(new URL('deployer-bootstrap-b0.json', base), 'utf8'));
const b1 = JSON.parse(await readFile(new URL('deployer-steady-b1.json', base), 'utf8'));

function actions(policy, effect = 'Allow') {
  return policy.Statement
    .filter((s) => s.Effect === effect)
    .flatMap((s) => Array.isArray(s.Action) ? s.Action : [s.Action]);
}
function resources(policy) {
  return policy.Statement.flatMap((s) => Array.isArray(s.Resource) ? s.Resource : [s.Resource]);
}
function statement(policy, sid) {
  const found = policy.Statement.find((s) => s.Sid === sid);
  assert.ok(found, `${sid} must exist`);
  return found;
}
for (const [name, policy] of [['B0', b0], ['B1', b1]]) {
  test(`${name} is valid bounded policy JSON with shared guardrails`, () => {
    assert.equal(policy.Version, '2012-10-17');
    assert.ok(Array.isArray(policy.Statement));
    assert.equal(actions(policy).includes('*'), false);
    assert.ok(statement(policy, 'DenyWrongRegion'));
    assert.ok(statement(policy, 'DenyProtectedResourceTags'));
    assert.ok(statement(policy, 'DenyProtectedRequestTags'));
    assert.ok(statement(policy, 'DenyProtectedStacks'));
    assert.match(JSON.stringify(policy), /ap-southeast-1/);
    assert.doesNotMatch(JSON.stringify(policy), /\b\d{12}\b/);
  });
}

test('B0 can provision only the bootstrap stack, artifact bucket family, and two named roles while reading its own SSO role family', () => {
  const allow = actions(b0);
  assert.ok(allow.includes('cloudformation:CreateStack'));
  assert.ok(allow.includes('s3:CreateBucket'));
  assert.ok(allow.includes('iam:CreateRole'));
  assert.equal(allow.some((a) => a.startsWith('sso:') || a.startsWith('sso-admin:')), false);
  const joined = resources(b0).join('\n');
  assert.match(joined, /stack\/ring-home-mcp-private-bootstrap/);
  assert.match(joined, /ring-home-mcp-private-artifacts-/);
  assert.match(joined, /role\/ring-home-mcp-private\/ring-home-mcp-private-cfn-exec/);
  assert.match(joined, /role\/ring-home-mcp-private\/ring-home-mcp-private-lambda-runtime/);
  assert.match(joined, /role\/aws-reserved\/sso\.amazonaws\.com\/ap-southeast-1\/AWSReservedSSO_example-admin_\*/);
  assert.doesNotMatch(joined, /stack\/ring-home-mcp-private\/\*/);
});

test('B1 is steady-state and cannot bootstrap IAM or buckets', () => {
  const allow = actions(b1);
  for (const forbidden of ['iam:CreateRole', 'iam:PutRolePolicy', 'iam:AttachRolePolicy', 's3:CreateBucket', 'sso:PutInlinePolicyToPermissionSet', 'sso:ProvisionPermissionSet']) {
    assert.equal(allow.includes(forbidden), false, `${forbidden} must remain absent`);
  }
  assert.ok(allow.includes('iam:PassRole'));
  assert.deepEqual(statement(b1, 'PassOnlyRingCloudFormationRole').Condition, { StringEquals: { 'iam:PassedToService': 'cloudformation.amazonaws.com' } });
  assert.match(resources(b1).join('\n'), /sam\/ring-home-mcp-private\/\*/);
});

test('B1 secret custody is write-only metadata bounded and never reads secret values', () => {
  const allow = actions(b1);
  assert.ok(allow.includes('secretsmanager:PutSecretValue'));
  assert.ok(allow.includes('secretsmanager:DescribeSecret'));
  assert.ok(allow.includes('secretsmanager:ListSecretVersionIds'));
  assert.equal(allow.includes('secretsmanager:GetSecretValue'), false);
  const write = statement(b1, 'TelegramSecretVersionWrite');
  assert.equal(typeof write.Resource, 'string');
  assert.match(write.Resource, /secret:ring-home-mcp-private\/telegram-\*$/);
});

test('B1 Dynamo metadata readback permits only the link and witness tables in ap-southeast-1', () => {
  const readback = statement(b1, 'DynamoMetadataReadback');
  assert.deepEqual(readback.Action, [
    'dynamodb:DescribeContinuousBackups',
    'dynamodb:DescribeTable',
    'dynamodb:DescribeTimeToLive',
    'dynamodb:ListTagsOfResource',
  ]);
  assert.deepEqual(readback.Resource, [
    'arn:aws:dynamodb:ap-southeast-1:*:table/ring-home-mcp-private-link',
    'arn:aws:dynamodb:ap-southeast-1:*:table/ring-home-mcp-private-witness',
  ]);
  for (const resource of readback.Resource) {
    assert.match(resource, /^arn:aws:dynamodb:ap-southeast-1:\*:table\/ring-home-mcp-private-(link|witness)$/);
    assert.doesNotMatch(resource, /table\/.*\*/);
    assert.doesNotMatch(resource, /other-stack-a|other-stack-b|other-stack-c/);
  }
});

test('protected projects appear only in explicit deny guardrails', () => {
  for (const policy of [b0, b1]) {
    for (const entry of policy.Statement) {
      const encoded = JSON.stringify(entry);
      if (/other-stack-a|other-stack-b|other-stack-c/.test(encoded)) {
        assert.equal(entry.Effect, 'Deny');
      }
    }
  }
});

test('B0 request-tag conditions apply only to role creation and tagging while S3 is region denied', () => {
  const create = statement(b0, 'BootstrapCreateTaggedRoles');
  const tag = statement(b0, 'BootstrapTagNamedRoles');
  const manage = statement(b0, 'BootstrapManageNamedRoles');
  assert.ok(create.Condition?.StringEquals?.['aws:RequestTag/Project']);
  assert.ok(tag.Condition?.StringEquals?.['aws:RequestTag/Project']);
  assert.equal('Condition' in manage, false);
  assert.ok((Array.isArray(manage.Action) ? manage.Action : [manage.Action]).includes('iam:PutRolePolicy'));
  assert.ok((Array.isArray(statement(b0, 'DenyWrongRegion').Action) ? statement(b0, 'DenyWrongRegion').Action : [statement(b0, 'DenyWrongRegion').Action]).includes('s3:*'));
});

test('B0 permits pathless bootstrap role ARNs only for pre-create GetRole inspection', () => {
  const pathlessRoleArns = [
    'arn:aws:iam::*:role/ring-home-mcp-private-cfn-exec',
    'arn:aws:iam::*:role/ring-home-mcp-private-lambda-runtime',
  ];
  const pathfulRoleArns = [
    'arn:aws:iam::*:role/ring-home-mcp-private/ring-home-mcp-private-cfn-exec',
    'arn:aws:iam::*:role/ring-home-mcp-private/ring-home-mcp-private-lambda-runtime',
  ];
  const read = statement(b0, 'BootstrapReadNamedRoles');
  const readActions = Array.isArray(read.Action) ? read.Action : [read.Action];
  const readResources = Array.isArray(read.Resource) ? read.Resource : [read.Resource];

  assert.deepEqual(readActions, ['iam:GetRole']);
  assert.deepEqual(new Set(readResources), new Set(pathlessRoleArns));

  for (const entry of b0.Statement.filter((candidate) => candidate.Effect === 'Allow' && candidate.Sid !== read.Sid)) {
    const entryResources = Array.isArray(entry.Resource) ? entry.Resource : [entry.Resource];
    const entryActions = Array.isArray(entry.Action) ? entry.Action : [entry.Action];
    for (const pathlessRoleArn of pathlessRoleArns) {
      assert.equal(entryResources.includes(pathlessRoleArn), false, `${entry.Sid} must not grant ${pathlessRoleArn}`);
    }
    if (entryActions.some((action) => action.startsWith('iam:') && !readActions.includes(action))) {
      assert.equal(entryResources.some((resource) => pathlessRoleArns.includes(resource)), false, `${entry.Sid} must not authorize pathless role writes`);
    }
  }
});

test('B0 reads only the ap-southeast-1 Ring Admin SSO role family for self-role inspection', () => {
  const selfRoleRead = statement(b0, 'BootstrapReadRingAdminSelfRole');
  assert.deepEqual(selfRoleRead, {
    Sid: 'BootstrapReadRingAdminSelfRole',
    Effect: 'Allow',
    Action: 'iam:GetRole',
    Resource: 'arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/ap-southeast-1/AWSReservedSSO_example-admin_*',
  });

  const selfRoleFamily = 'AWSReservedSSO_example-admin_';
  const matchingStatements = b0.Statement.filter((entry) => JSON.stringify(entry).includes(selfRoleFamily));
  assert.deepEqual(matchingStatements, [selfRoleRead]);
  assert.equal(selfRoleRead.Resource.includes(':role/aws-reserved/sso.amazonaws.com/ap-southeast-1/'), true);
  assert.equal(selfRoleRead.Resource.includes(':role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_'), false);
});

test('B0 covers the AWS IAM Role read and rollback handler for pathful roles only', () => {
  const manage = statement(b0, 'BootstrapManageNamedRoles');
  const manageActions = new Set(Array.isArray(manage.Action) ? manage.Action : [manage.Action]);
  const requiredHandlerActions = [
    'iam:DeleteRole',
    'iam:DeleteRolePolicy',
    'iam:GetRole',
    'iam:GetRolePolicy',
    'iam:ListAttachedRolePolicies',
    'iam:ListRolePolicies',
    'iam:UntagRole',
  ];
  for (const action of requiredHandlerActions) assert.ok(manageActions.has(action), `${action} is required by the role handler lifecycle`);
  assert.deepEqual(statement(b0, 'BootstrapTagNamedRoles').Action, 'iam:TagRole');
  assert.equal(manageActions.has('iam:AttachRolePolicy'), false);
  assert.equal(manageActions.has('iam:DetachRolePolicy'), false);
  const resources = Array.isArray(manage.Resource) ? manage.Resource : [manage.Resource];
  assert.ok(resources.every((resource) => resource.includes(':role/ring-home-mcp-private/')));
});

test('B0 admits exact-stack cleanup and read-only retained-bucket inspection', () => {
  const lifecycle = statement(b0, 'BootstrapStackLifecycle');
  const lifecycleActions = new Set(Array.isArray(lifecycle.Action) ? lifecycle.Action : [lifecycle.Action]);
  assert.ok(lifecycleActions.has('cloudformation:DeleteStack'));
  assert.ok(lifecycleActions.has('cloudformation:DetectStackDrift'));
  assert.ok(lifecycleActions.has('cloudformation:DetectStackResourceDrift'));
  assert.ok(lifecycleActions.has('cloudformation:DescribeStackResourceDrifts'));
  assert.equal(lifecycleActions.has('cloudformation:BatchDescribeTypeConfigurations'), false);
  assert.equal(lifecycleActions.has('cloudformation:DescribeStackDriftDetectionStatus'), false);
  assert.match(lifecycle.Resource, /stack\/ring-home-mcp-private-bootstrap\/\*$/);

  const driftTypeConfiguration = statement(b0, 'BootstrapDriftTypeConfigurationRead');
  assert.equal(driftTypeConfiguration.Action, 'cloudformation:BatchDescribeTypeConfigurations');
  assert.equal(driftTypeConfiguration.Resource, '*');

  const driftStatus = statement(b0, 'BootstrapDriftStatusRead');
  assert.equal(driftStatus.Action, 'cloudformation:DescribeStackDriftDetectionStatus');
  assert.equal(driftStatus.Resource, '*');
  const mandatoryDriftActions = new Set([
    ...lifecycleActions,
    driftTypeConfiguration.Action,
    driftStatus.Action,
  ]);
  for (const action of [
    'cloudformation:DetectStackDrift',
    'cloudformation:DetectStackResourceDrift',
    'cloudformation:BatchDescribeTypeConfigurations',
    'cloudformation:DescribeStackResourceDrifts',
    'cloudformation:DescribeStackDriftDetectionStatus',
  ]) assert.ok(mandatoryDriftActions.has(action), `${action} is required for stack drift detection`);
  assert.equal(b0.Statement.length, 14);
  const describeResourceDriftsStatements = b0.Statement.filter((entry) => {
    const entryActions = Array.isArray(entry.Action) ? entry.Action : [entry.Action];
    return entryActions.includes('cloudformation:DescribeStackResourceDrifts');
  });
  assert.equal(describeResourceDriftsStatements.length, 1);
  assert.equal(describeResourceDriftsStatements[0].Sid, 'BootstrapStackLifecycle');
  assert.match(describeResourceDriftsStatements[0].Resource, /stack\/ring-home-mcp-private-bootstrap\/\*$/);
  const broadCloudFormationAllows = b0.Statement.filter((entry) => {
    if (entry.Effect !== 'Allow') return false;
    const entryActions = Array.isArray(entry.Action) ? entry.Action : [entry.Action];
    return entryActions.includes('cloudformation:*') || entryActions.includes('*');
  });
  assert.equal(broadCloudFormationAllows.length, 0);
  const unscopedAllows = b0.Statement.filter((entry) => entry.Effect === 'Allow' && entry.Resource === '*');
  assert.deepEqual(
    unscopedAllows.map((entry) => entry.Sid).sort(),
    ['BootstrapDriftStatusRead', 'BootstrapDriftTypeConfigurationRead', 'CallerIdentity'],
  );
  assert.deepEqual(
    unscopedAllows.flatMap((entry) => Array.isArray(entry.Action) ? entry.Action : [entry.Action]).sort(),
    ['cloudformation:BatchDescribeTypeConfigurations', 'cloudformation:DescribeStackDriftDetectionStatus', 'sts:GetCallerIdentity'],
  );

  const bucket = statement(b0, 'BootstrapArtifactBucket');
  const bucketActions = new Set(Array.isArray(bucket.Action) ? bucket.Action : [bucket.Action]);
  for (const action of [
    's3:GetEncryptionConfiguration',
    's3:GetLifecycleConfiguration',
    's3:GetBucketNotification',
    's3:GetBucketObjectLockConfiguration',
    's3:GetReplicationConfiguration',
    's3:ListBucket',
    's3:ListBucketMultipartUploads',
    's3:ListBucketVersions',
  ]) assert.ok(bucketActions.has(action), `${action} is required for the retained-bucket gate`);
  for (const action of [
    's3:PutEncryptionConfiguration',
    's3:PutLifecycleConfiguration',
  ]) assert.ok(bucketActions.has(action), `${action} is required for bootstrap provisioning`);
  for (const invalidAction of [
    's3:GetBucketEncryption',
    's3:GetBucketLifecycleConfiguration',
    's3:PutBucketEncryption',
    's3:PutBucketLifecycleConfiguration',
  ]) assert.equal(bucketActions.has(invalidAction), false, `${invalidAction} is an API operation label, not the IAM action`);
  for (const action of ['s3:DeleteObject', 's3:DeleteObjectVersion']) assert.equal(bucketActions.has(action), false);
});

test('B1 separates bucket location from prefix list and binds change-set creation to the exact execution role', () => {
  const location = statement(b1, 'ArtifactBucketLocation');
  const list = statement(b1, 'ArtifactBucketList');
  const create = statement(b1, 'ApplicationChangeSetCreate');
  assert.equal('Condition' in location, false);
  assert.deepEqual(list.Condition, { StringLike: { 's3:prefix': ['sam/ring-home-mcp-private', 'sam/ring-home-mcp-private/*'] } });
  assert.deepEqual(create.Condition, { ArnLike: { 'cloudformation:RoleArn': 'arn:aws:iam::*:role/ring-home-mcp-private/ring-home-mcp-private-cfn-exec' } });
  const lifecycle = actions({ Statement: [statement(b1, 'ApplicationStackLifecycle')] });
  assert.equal(lifecycle.includes('cloudformation:CreateStack'), false);
  assert.equal(lifecycle.includes('cloudformation:UpdateStack'), false);
  assert.equal(lifecycle.includes('cloudformation:CreateChangeSet'), false);
});
