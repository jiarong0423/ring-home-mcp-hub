import { createRingOfficialClient } from "../src/ring_official_client.mjs";

if (process.argv.length !== 2) {
  process.stderr.write("This probe accepts no command-line arguments.\n");
  process.exitCode = 2;
} else {
  const client = createRingOfficialClient({
    tokenProvider: () => process.env.RING_PLAYGROUND_ACCESS_TOKEN,
  });
  const result = await client.discoverDevices();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = result.configured ? 1 : 2;
}
