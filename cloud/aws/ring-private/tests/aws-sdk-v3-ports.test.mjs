import test from 'node:test';
import assert from 'node:assert/strict';
import {
  GetItemCommand,
  UpdateItemCommand,
  QueryCommand,
  TransactGetItemsCommand,
  TransactWriteItemsCommand
} from '@aws-sdk/client-dynamodb';
import { DecryptCommand, GenerateDataKeyCommand } from '@aws-sdk/client-kms';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
  createAwsSdkV3Clients,
  createAwsSdkV3Ports
} from '../aws-sdk-v3-ports.mjs';

function recordingClient(output) {
  const calls = [];
  return {
    calls,
    client: {
      async send(command) {
        calls.push(command);
        return output;
      }
    }
  };
}

test('low-level adapters create the exact accepted DynamoDB, KMS and Secrets Manager commands', async () => {
  const dynamo = recordingClient({ dynamo: true });
  const kms = recordingClient({ kms: true });
  const secrets = recordingClient({ secrets: true });
  const ports = createAwsSdkV3Ports({
    dynamoDbClient: dynamo.client,
    kmsClient: kms.client,
    secretsManagerClient: secrets.client
  });
  const inputs = {
    query: { TableName: 'GeneratedRingTable', Limit: 1 },
    getItem: { TableName: 'GeneratedRingTable', Key: { PK: { S: 'A' }, SK: { S: 'B' } } },
    transactGet: { TransactItems: [{ Get: { TableName: 'GeneratedRingTable', Key: { PK: { S: 'A' }, SK: { S: 'B' } } } }] },
    transactWrite: { TransactItems: [{ ConditionCheck: { TableName: 'GeneratedRingTable', Key: { PK: { S: 'A' }, SK: { S: 'B' } }, ConditionExpression: 'attribute_exists(PK)' } }] },
    generateDataKey: { KeyId: 'alias/generated-ring', KeySpec: 'AES_256' },
    decryptDataKey: { KeyId: 'alias/generated-ring', CiphertextBlob: Buffer.from('generated') },
    getSecretValue: { SecretId: 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated' }
  };
  assert.deepEqual(await ports.query(inputs.query), { dynamo: true });
  assert.deepEqual(await ports.getItem(inputs.getItem), { dynamo: true });
  assert.deepEqual(await ports.transactGet(inputs.transactGet), { dynamo: true });
  assert.deepEqual(await ports.transactWrite(inputs.transactWrite), { dynamo: true });
  assert.deepEqual(await ports.generateDataKey(inputs.generateDataKey), { kms: true });
  assert.deepEqual(await ports.decryptDataKey(inputs.decryptDataKey), { kms: true });
  assert.deepEqual(await ports.getSecretValue(inputs.getSecretValue), { secrets: true });
  assert.deepEqual(dynamo.calls.map(command => command.constructor), [QueryCommand, GetItemCommand, TransactGetItemsCommand, TransactWriteItemsCommand]);
  assert.deepEqual(kms.calls.map(command => command.constructor), [GenerateDataKeyCommand, DecryptCommand]);
  assert.deepEqual(secrets.calls.map(command => command.constructor), [GetSecretValueCommand]);
  assert.equal(dynamo.calls[0].input, inputs.query);
  assert.equal(kms.calls[0].input, inputs.generateDataKey);
  assert.equal(secrets.calls[0].input, inputs.getSecretValue);
});

test('official clients pin region and one attempt without an endpoint override', async () => {
  const clients = createAwsSdkV3Clients({ region: 'ap-southeast-1' });
  try {
    for (const client of Object.values(clients)) {
      assert.equal(await client.config.region(), 'ap-southeast-1');
      assert.equal(await client.config.maxAttempts(), 1);
      assert.equal(client.config.endpoint, undefined);
      assert.equal(typeof client.config.credentials, 'function');
    }
  } finally {
    for (const client of Object.values(clients)) client.destroy();
  }
});

test('request AbortSignal is forwarded as the AWS SDK abortSignal on every port', async () => {
  const calls = [];
  const client = {
    async send(command, options) {
      calls.push({ command, options });
      return {};
    }
  };
  const ports = createAwsSdkV3Ports({
    dynamoDbClient: client,
    kmsClient: client,
    secretsManagerClient: client
  });
  const controller = new AbortController();
  await ports.getItem({ TableName: 'GeneratedRingTable', Key: { PK: { S: 'A' } } }, { signal: controller.signal });
  await ports.putItem({ TableName: 'GeneratedRingTable', Item: { PK: { S: 'A' } } }, { signal: controller.signal });
  await ports.getSecretValue({ SecretId: 'generated' }, { signal: controller.signal });
  assert.equal(calls.length, 3);
  assert.equal(calls.every(call => call.options.abortSignal === controller.signal), true);
});

test('client and adapter factories reject extra, missing, accessor and proxy configuration', () => {
  assert.throws(() => createAwsSdkV3Clients({ region: 'ap-southeast-1', endpoint: 'http://127.0.0.1' }), /aws_sdk_ports_config/);
  assert.throws(() => createAwsSdkV3Clients({ region: 'invalid' }), /aws_sdk_ports_config/);
  assert.throws(() => createAwsSdkV3Ports({}), /aws_sdk_ports_config/);
  let invoked = 0;
  const getter = Object.defineProperty({}, 'region', {
    enumerable: true,
    get() {
      invoked += 1;
      return 'ap-southeast-1';
    }
  });
  assert.throws(() => createAwsSdkV3Clients(getter), /aws_sdk_ports_config/);
  assert.throws(() => createAwsSdkV3Clients(new Proxy({}, {
    ownKeys() {
      invoked += 1;
      return [];
    }
  })), /aws_sdk_ports_config/);
  assert.equal(invoked, 0);
});


test('UpdateItem port preserves input identity and AbortSignal without unrelated clients', async () => {
  const calls = [];
  const client = { async send(command, options) { calls.push({ command, options }); return { Attributes: {} }; } };
  const forbidden = { send() { assert.fail('unrelated client'); } };
  const ports = createAwsSdkV3Ports({ dynamoDbClient: client, kmsClient: forbidden, secretsManagerClient: forbidden });
  const input = { TableName: 'ring-home-mcp-private-witness', ConditionExpression: '#phase = :confirmed' };
  const controller = new AbortController();
  assert.deepEqual(await ports.updateItem(input, { signal: controller.signal }), { Attributes: {} });
  assert.equal(calls.length, 1); assert.ok(calls[0].command instanceof UpdateItemCommand);
  assert.equal(calls[0].command.input, input); assert.equal(calls[0].options.abortSignal, controller.signal);
});
