import { types } from 'node:util';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  QueryCommand,
  TransactGetItemsCommand,
  TransactWriteItemsCommand
} from '@aws-sdk/client-dynamodb';
import {
  DecryptCommand,
  GenerateDataKeyCommand,
  KMSClient
} from '@aws-sdk/client-kms';
import {
  GetSecretValueCommand,
  SecretsManagerClient
} from '@aws-sdk/client-secrets-manager';

const REGION = /^(?:af|ap|ca|eu|il|me|mx|sa|us|cn)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]*$/;

function fail() {
  throw new TypeError('aws_sdk_ports_config');
}

function exactData(value, required) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (required.some(key => !Object.hasOwn(descriptors, key)) || keys.length !== required.length ||
        keys.some(key => typeof key !== 'string' || !required.includes(key) ||
          !Object.hasOwn(descriptors[key], 'value'))) fail();
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch {
    fail();
  }
}

function sender(client) {
  try {
    if (client === null || typeof client !== 'object' || types.isProxy(client)) fail();
    let owner = client;
    let descriptor;
    while (owner !== null) {
      if (types.isProxy(owner)) fail();
      descriptor = Object.getOwnPropertyDescriptor(owner, 'send');
      if (descriptor) break;
      owner = Object.getPrototypeOf(owner);
    }
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)) fail();
    return descriptor.value.bind(client);
  } catch {
    fail();
  }
}

function sendOptions(value) {
  if (value === undefined) return undefined;
  const { signal } = exactData(value, ['signal']);
  try {
    if (typeof AbortSignal === 'undefined' || !(signal instanceof AbortSignal)) fail();
  } catch {
    fail();
  }
  return Object.freeze({ abortSignal: signal });
}

function execute(send, Command, input, options) {
  const request = new Command(input);
  const selected = sendOptions(options);
  return selected === undefined ? send(request) : send(request, selected);
}

export function createAwsSdkV3Clients(options) {
  const { region } = exactData(options, ['region']);
  if (typeof region !== 'string' || !REGION.test(region)) fail();
  const clientConfig = Object.freeze({ region, maxAttempts: 1 });
  return Object.freeze({
    dynamoDbClient: new DynamoDBClient(clientConfig),
    kmsClient: new KMSClient(clientConfig),
    secretsManagerClient: new SecretsManagerClient(clientConfig)
  });
}

export function createAwsSdkV3Ports(options) {
  const { dynamoDbClient, kmsClient, secretsManagerClient } = exactData(options, [
    'dynamoDbClient',
    'kmsClient',
    'secretsManagerClient'
  ]);
  const sendDynamo = sender(dynamoDbClient);
  const sendKms = sender(kmsClient);
  const sendSecrets = sender(secretsManagerClient);
  return Object.freeze({
    query: (input, options) => execute(sendDynamo, QueryCommand, input, options),
    getItem: (input, options) => execute(sendDynamo, GetItemCommand, input, options),
    putItem: (input, options) => execute(sendDynamo, PutItemCommand, input, options),
    updateItem: (input, options) => execute(sendDynamo, UpdateItemCommand, input, options),
    transactGet: (input, options) => execute(sendDynamo, TransactGetItemsCommand, input, options),
    transactWrite: (input, options) => execute(sendDynamo, TransactWriteItemsCommand, input, options),
    generateDataKey: (input, options) => execute(sendKms, GenerateDataKeyCommand, input, options),
    decryptDataKey: (input, options) => execute(sendKms, DecryptCommand, input, options),
    getSecretValue: (input, options) => execute(sendSecrets, GetSecretValueCommand, input, options)
  });
}

export function createDefaultAwsSdkV3Ports(options) {
  return createAwsSdkV3Ports(createAwsSdkV3Clients(options));
}
