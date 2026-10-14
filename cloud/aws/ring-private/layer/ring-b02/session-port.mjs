// Keep a single /var/task module instance so request-bound OAuth evidence is shared.
export async function createRingB02SessionSeam() {
  const runtime = await import('file:///var/task/cloud/aws/ring-private/b02-layer-runtime.mjs');
  return runtime.createRingB02SessionSeam();
}
