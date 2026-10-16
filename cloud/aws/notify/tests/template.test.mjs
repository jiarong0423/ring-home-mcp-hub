// Contract for the independent alerts stack: exactly the planned resource kinds, least-privilege IAM, a dead-man alarm that
// treats missing heartbeats as an alarm, and nothing that touches the ring-private stack or mints an access key.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const template = JSON.parse(readFileSync(new URL('../notify-template.json', import.meta.url), 'utf8'));
const resources = Object.entries(template.Resources);

test('only SNS topic + email subscription, one CloudWatch alarm, one IAM user + its policy', () => {
  assert.deepEqual(resources.map(([, r]) => r.Type).sort(),
    ['AWS::CloudWatch::Alarm', 'AWS::IAM::Policy', 'AWS::IAM::User', 'AWS::SNS::Subscription', 'AWS::SNS::Topic']);
  assert.equal(resources.some(([, r]) => r.Type === 'AWS::IAM::AccessKey'), false, 'the stack never creates an access key');
  assert.equal(JSON.stringify(template).includes('ring-private'), false);
  assert.equal(template.Resources.AlertsEmailSubscription.Properties.Protocol, 'email');
});

test('IAM: two fixed statements (this topic only; HomeMcp metrics only) plus Bedrock only when exact model ARNs are given', () => {
  const policy = template.Resources.NotifierPolicy.Properties;
  assert.deepEqual(policy.Users, [{ Ref: 'NotifierUser' }]);
  const all = policy.PolicyDocument.Statement;
  assert.equal(all.length, 3);
  // optional third statement: InvokeModel on the listed ARNs only, absent when the parameter is empty (the default)
  const optional = all[2]['Fn::If'];
  assert.equal(optional[0], 'CareSummaryEnabled');
  assert.deepEqual(optional[1], { Sid: 'InvokeCareSummaryModelOnly', Effect: 'Allow', Action: 'bedrock:InvokeModel', Resource: { Ref: 'CareSummaryModelArns' } });
  assert.deepEqual(optional[2], { Ref: 'AWS::NoValue' });
  assert.equal(template.Parameters.CareSummaryModelArns.Default, '');
  assert.deepEqual(template.Conditions.CareSummaryEnabled, { 'Fn::Not': [{ 'Fn::Equals': [{ 'Fn::Join': ['', { Ref: 'CareSummaryModelArns' }] }, ''] }] });
  const statements = all.slice(0, 2);
  assert.ok(statements.every((s) => s.Effect === 'Allow' && typeof s.Action === 'string' && !s.Action.includes('*')));
  const publish = statements.find((s) => s.Action === 'sns:Publish');
  assert.deepEqual(publish.Resource, { Ref: 'AlertsTopic' });
  const metric = statements.find((s) => s.Action === 'cloudwatch:PutMetricData');
  assert.deepEqual(metric.Condition, { StringEquals: { 'cloudwatch:namespace': 'HomeMcp' } });
  assert.equal(template.Resources.NotifierUser.Properties.UserName, undefined, 'unnamed user: CAPABILITY_IAM only');
});

test('dead-man alarm: missing heartbeats breach, alarm and recovery both email the family topic', () => {
  const a = template.Resources.HubSilentAlarm.Properties;
  assert.equal(a.Namespace, 'HomeMcp'); assert.equal(a.MetricName, 'HubHeartbeat');
  assert.equal(a.TreatMissingData, 'breaching');
  assert.equal(a.Period, 300); assert.equal(a.ComparisonOperator, 'LessThanThreshold'); assert.equal(a.Threshold, 1);
  assert.deepEqual(a.EvaluationPeriods, { Ref: 'HubSilentPeriods' });
  assert.deepEqual(a.AlarmActions, [{ Ref: 'AlertsTopic' }]); assert.deepEqual(a.OKActions, [{ Ref: 'AlertsTopic' }]);
  const p = template.Parameters.HubSilentPeriods;
  assert.deepEqual([p.Default, p.MinValue, p.MaxValue], [3, 1, 12]);
});

test('email parameter accepts one address and rejects lists or injected text', () => {
  const re = new RegExp(template.Parameters.AlertEmail.AllowedPattern, 'u');
  for (const ok of ['family@example.com', 'a.b+home@example.co']) assert.ok(re.test(ok), ok);
  for (const bad of ['a@b.com,c@d.com', 'a@b.com c@d.com', 'not-an-email', '@example.com', 'a@b']) assert.equal(re.test(bad), false, bad);
});
