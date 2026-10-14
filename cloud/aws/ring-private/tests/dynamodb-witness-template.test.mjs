import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const template = await readFile(new URL('../template.yaml', import.meta.url), 'utf8');
const bootstrap = await readFile(new URL('../bootstrap-template.yaml', import.meta.url), 'utf8');
const table = template.slice(template.indexOf('  RingPrivateWitnessTable:\n'), template.indexOf('  RingPrivateProviderSecret:\n'));
function statement(name) { const start = bootstrap.indexOf(`              - Sid: ${name}\n`); assert.notEqual(start, -1); const end = bootstrap.indexOf('              - Sid:', start + 20); return bootstrap.slice(start, end); }
test('dedicated witness has retention, KMS SSE, PITR, deletion protection and exact sole key', () => {
  for (const fragment of ['Type: AWS::DynamoDB::Table', 'DeletionPolicy: Retain', 'UpdateReplacePolicy: Retain',
    'TableName: ring-home-mcp-private-witness', 'BillingMode: PAY_PER_REQUEST', 'DeletionProtectionEnabled: true',
    'PointInTimeRecoveryEnabled: true', 'SSEEnabled: true', 'SSEType: KMS', 'KMSMasterKeyId: !GetAtt RingPrivateTokenKey.Arn',
    '{AttributeName: witness_id, AttributeType: S}', '{AttributeName: witness_id, KeyType: HASH}']) assert.ok(table.includes(fragment), fragment);
  assert.equal((table.match(/AttributeName:/g) ?? []).length, 2);
  assert.doesNotMatch(table, /TimeToLive|StreamSpecification|GlobalSecondary|LocalSecondary|KeyType: RANGE/);
});
test('runtime and deployment witness IAM are exact-table allowlists without delete, scan, query or wildcard', () => {
  const data = statement('RingPrivateWitnessData'); const deploy = statement('ManageRingPrivateWitnessTable');
  assert.deepEqual([...data.matchAll(/- (dynamodb:[A-Za-z]+)/g)].map(x => x[1]).sort(), ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'].sort());
  assert.deepEqual([...deploy.matchAll(/- (dynamodb:[A-Za-z]+)/g)].map(x => x[1]).sort(), ['CreateTable', 'DescribeTable', 'DescribeContinuousBackups', 'ListTagsOfResource', 'TagResource', 'UpdateTable', 'UpdateContinuousBackups'].map(x => `dynamodb:${x}`).sort());
  for (const block of [data, deploy]) {
    assert.match(block, /Resource: !Sub arn:\$\{AWS::Partition\}:dynamodb:\$\{AWS::Region\}:\$\{AWS::AccountId\}:table\/ring-home-mcp-private-witness\n/);
    assert.doesNotMatch(block, /Delete|Scan|Query|Batch|Transact|TimeToLive|\*/);
  }
});
test('witness environment pins existing-only mode without public API or initialization parameter', () => {
  assert.match(template, /RING_WITNESS_TABLE_NAME: !Ref RingPrivateWitnessTable/);
  assert.match(template, /RING_WITNESS_ID: formal-runtime-primary-v1/);
  assert.match(template, /RING_WITNESS_MODE: REQUIRE_EXISTING/);
  assert.doesNotMatch(template, /ALLOW_EMPTY_ONCE|PathPart: witness|WitnessUrl|WitnessMode:/);
  assert.equal((template.match(/AWS::ApiGateway::Method/g) ?? []).length, 4);
});
