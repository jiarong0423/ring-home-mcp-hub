# Friction log

Problems we hit while building Ring Home MCP Hub with the Ring Developer Playground and AWS, with what we did about them.

| # | Task attempted | Steps taken | Expected vs. actual | Severity | Workaround used | Actionable suggestion |
|---|---|---|---|---|---|---|
| 1 | Link a real Ring account to our app | Created a developer app; started account linking from a Taiwan-region account | **Expected:** an OAuth consent flow. **Actual:** account linking was not available for a non-US account | High | Verified the owner with a Ring Developer Playground sandbox token (`GET /v1/users/me`) and pinned the Ring account (SHA-256) to the owner in our cloud | Allow sandbox account linking in all regions, or document a test-account path for non-US developers |
| 2 | Re-run owner verification after a break | Reused a Playground token copied earlier | **Expected:** a clear "token expired" error. **Actual:** a plain HTTP 401 | Medium | Added a read-only `/v1/users/me` check that tells token expiry apart from other errors | Return a `token_expired` error code, and show the expiry time next to the generated token |
| 3 | Test a device action end to end | Looked for a controllable device in the Playground sandbox | **Expected:** a simulated device that accepts actions. **Actual:** read-only discovery only | Medium | Built seven simulated devices in our local console, behind the same allowlist the cloud enforces | Provide a Ring device simulator with safe actions (for example light on/off, arm) and event callbacks |
| 4 | Keep a pinned API Gateway admission valid after a redeploy | Redeployed the REST API after adding a route; invoked through the console test-invoke and through the real stage | **Expected:** the pinned values stay the same. **Actual:** real stage requests carried a new `deploymentId`, the console test-invoke did not, so our pinned admission rejected real traffic | Medium | Rebuilt and re-signed the admission file for the new deployment | Document that test-invoke omits `requestContext.deploymentId` |
| 5 | Iterate on the deployer IAM policy | Published a new managed-policy version for each deploy step | **Expected:** create a new version. **Actual:** the 5-version limit blocked the update | Low | Deleted the oldest unused version after review | Show the version limit and the oldest non-default version in the error message |

## Feature requests

1. **Longer-lived sandbox credential or refresh token for the Ring Developer Playground.** Lets hubs and agents run unattended during development; today tokens expire after about 30 minutes. *Important.*
2. **A Ring device simulator with safe write actions and event webhooks.** Lets developers test access-control and automation flows end to end without hardware. *Important.*
3. **Sandbox account linking for non-US developer accounts.** This was our biggest onboarding blocker. *Critical for a global hackathon.*
