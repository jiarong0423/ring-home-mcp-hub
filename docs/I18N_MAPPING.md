# I18N_MAPPING — UI text mapping table (中文 ↔ English)

> Generated file — do not edit by hand. Regenerate with `node scripts/gen_i18n_mapping.mjs` (check only: `node scripts/gen_i18n_mapping.mjs --check`).

English is the default UI language; Chinese is available with `?lang=zh`.

* Source of truth: `public/i18n-map.mjs` (`I18N_MAP`, frozen `{ key: { en, zh } }`, plus `t(key, params)`). This file is generated from the same table.
* Default language: **English**. Chinese: open `http://127.0.0.1:8765/?lang=zh` (or click the `中文` / `English` link in the header; it reloads the page, so pick the language **before** logging in).
* Markup uses `data-i18n="key"` / `data-i18n-aria-label="key"`; scripts call `t('key', { param })`. `{name}` = runtime parameter.
* "where used" is computed by scanning `public/*.html`, `public/*.mjs` and `src/*.mjs` for the key as a literal, or for a dynamic prefix (a string literal ending in a dot such as `'a.b.' + x`, or `` `a.b.${x}` ``). "unused key" = no reference found.
* `cloud.*` keys belong to the optional earlier-phase Cloud MCP panel, shown only when the server starts with `HOME_MCP_CLOUD_PANEL=1`. Its step lines are sent as stable codes `{ key: 'cloud.step.*', params }` by `src/cloud_mcp_panel.mjs` and rendered by the client through this table.
* Not translated (by design): protocol / code values shown verbatim (`result.status=SUCCEEDED`, `executed=true`, `commandId=cmd_…`, error codes such as `MAC_KEY_NOT_READY`, device ids), audit `outcome`/`action` codes from the simulator, device icons (◇ ❄ ▣ ◷ ☼ ◎ ♧) and the brand mark `M`.

Total keys: **619**

| key | 中文 | English | where used |
| --- | --- | --- | --- |
| `locale` | zh-TW | en-US | cloud-mcp-panel.mjs, faces.mjs, i18n-map.mjs, phone-pair.mjs |
| `html.lang` | zh-Hant | en | i18n-map.mjs |
| `lang.toggle` | English | 中文 | index.html header |
| `lang.toggleAria` | 切換為英文介面 | Switch the interface to Chinese | index.html header (aria-label) |
| `page.title` | Home MCP Guardian 居家守護 | Home MCP Guardian | index.html |
| `brand.name` | Home MCP | Home MCP | index.html header |
| `header.subtitle` | Ring 看門 · 家人手機決定 · AI 只能提出請求 | Ring at the door · a family phone decides · AI can only ask | index.html header |
| `header.badge` | SIMULATED | SIMULATED | index.html header |
| `header.note` | 七設備、家庭閘道與門鎖皆為軟體模擬 · 載入 Ring Playground token 時 Ring API 為真實呼叫（未載入則同為模擬）· 不控制任何 Wi‑Fi 或硬體 | Seven devices are SIMULATED, plus the home gateway and door lock · Ring API is real while a Playground token is loaded (simulated without one) · No Wi‑Fi or hardware is controlled | index.html header |
| `header.logout` | 登出 | Log out | index.html header |
| `login.heading` | 進入私人控制介面 | Enter the private control console | index.html |
| `login.intro` | 輸入本機示範通行碼。此頁只模擬裝置、配對與指令，不會控制家中設備。 | Enter the local demo passcode. This page only simulates devices, pairing and commands; it does not control any home device. | index.html |
| `login.passcode.label` | 示範通行碼 | Demo passcode | index.html |
| `login.passcode.hint` | 通行碼由本機伺服器提供；請勿輸入真實帳號密碼。 | The passcode comes from the local server; do not enter a real account password. | index.html |
| `login.submit` | 登入模擬控制台 | Log in to the simulated console | index.html |
| `hero.heading` | 居家守護：門口、每日例行，以及守護系統本身 | Home guardian: the door, the routine and the guardian itself | index.html |
| `hero.intro` | 七個模擬設備共用配對、每日例行與同一份稽核紀錄；開門一律要信任的家人手機核准。 | Seven simulated devices share pairing, a daily routine and one audit trail; opening the door always needs a trusted family phone. | index.html |
| `hero.endpoint` | 本機 MCP 端點 | Local MCP endpoint | index.html |
| `hero.copyToken` | 複製本次 MCP 權杖 | Copy this session’s MCP token | index.html |
| `hero.tokenNote` | 僅供本機模擬器，不是 Wi‑Fi 密碼 | Local simulator only; not a Wi‑Fi password | index.html |
| `hero.statsAria` | 設備摘要 | Device summary | index.html (aria-label) |
| `hero.stat.devices` | 虛擬設備 | Virtual devices | index.html |
| `hero.stat.paired` | 已模擬配對 | Simulated pairings | index.html |
| `hero.stat.schedules` | 待執行排程 | Pending schedules | index.html |
| `wifi.title` | 家庭 Wi-Fi 授權 | Home Wi-Fi authorization | index.html |
| `wifi.intro` | 家庭 Wi-Fi 只用來選擇本地加密傳輸。進入 MCP 時，系統仍會自動簽發短效憑證。 | Home Wi-Fi is only used to select local encrypted transport. Entering MCP still issues a short-lived credential automatically. | index.html |
| `wifi.status.initial` | 尚未讀取家庭 Wi-Fi 授權狀態。 | Home Wi-Fi authorization status not read yet. | index.html |
| `wifi.authorize` | 授權此家庭 Wi-Fi | Authorize this home Wi-Fi | index.html |
| `wifi.revoke` | 撤銷家庭 Wi-Fi 授權 | Revoke home Wi-Fi authorization | index.html |
| `wifi.phase.disabled` | 家庭 Wi-Fi 授權尚未啟用。正式家庭身分連接完成前，不會建立替代身分或本地信任。 | Home Wi-Fi authorization is not enabled. Until the formal household identity is connected, no substitute identity or local trust is created. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.idle` | 尚未讀取家庭 Wi-Fi 授權狀態。家庭 Wi-Fi 只用來選擇本地加密傳輸；進入 MCP 時仍會自動簽發短效憑證。 | Home Wi-Fi authorization status not read yet. Home Wi-Fi only selects local encrypted transport; entering MCP still issues a short-lived credential automatically. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.pending` | 正在處理家庭 Wi-Fi 授權，請稍候。 | Processing home Wi-Fi authorization, please wait. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.active` | 已授權此家庭 Wi-Fi。它只會選擇本地加密傳輸；進入 MCP 時仍會自動簽發短效憑證。 | This home Wi-Fi is authorized. It only selects local encrypted transport; entering MCP still issues a short-lived credential automatically. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.revoked` | 家庭 Wi-Fi 授權已撤銷。下次進入 MCP 時仍會依入口規則自動簽發短效憑證。 | Home Wi-Fi authorization revoked. The next MCP entry still issues a short-lived credential automatically under the entry rules. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.denied` | 家庭 Wi-Fi 授權未通過。請確認授權意願後再試一次。 | Home Wi-Fi authorization was not granted. Confirm your consent and try again. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `wifi.phase.adapter-error` | 無法讀取或更新家庭 Wi-Fi 授權。請稍後再試。 | Could not read or update home Wi-Fi authorization. Please try again later. | wifi-permission-controller.mjs (dynamic `wifi.phase.*`) |
| `localRing.heading` | 本地 Ring 主線 · SIMULATED | Local Ring mainline · SIMULATED | index.html |
| `localRing.intro` | 產生模擬身分與一次性綁定，再將模擬 Motion 排入本地佇列。按「執行模擬 worker」後才檢查最新授權並操作客廳燈。撤銷或登出會阻止後續命令；重新啟動可建立全新模擬資料。未連接 Ring、AWS 或實體設備。 | Create a simulated identity and one-time binding, then queue a simulated Motion locally. Only "Run simulated worker" checks the latest authorization and operates the living room light. Revoking or logging out blocks later commands; restarting creates fresh simulated data. No Ring, AWS or physical device is connected. | index.html |
| `localRing.link` | 建立模擬身分與綁定 | Create simulated identity and binding | index.html |
| `localRing.motion` | 模擬 Motion 入列 | Queue simulated Motion | index.html |
| `localRing.worker` | 執行模擬 worker | Run simulated worker | index.html |
| `localRing.offline` | worker 離線 | Worker offline | index.html |
| `localRing.online` | worker 上線 | Worker online | index.html |
| `localRing.remove` | 撤銷模擬帳戶 | Revoke simulated account | index.html |
| `localRing.identity.unlinked` | 尚未綁定 | Not bound yet | index.html (script) |
| `localRing.identity.authenticated` | 模擬身分有效 | Simulated identity valid | index.html (script) |
| `localRing.identity.revoked` | 帳戶已撤銷 | Account revoked | index.html (script) |
| `localRing.identity.logged_out` | 模擬身分已登出 | Simulated identity logged out | index.html (script) |
| `localRing.authExpired` | 模擬授權已過期或不可用 | Simulated authorization expired or unavailable | index.html (script) |
| `localRing.authPending` | 授權待檢查 | Authorization pending check | index.html (script) |
| `localRing.workerOnline` | 上線 | online | index.html (script) |
| `localRing.workerOffline` | 離線 | offline | index.html (script) |
| `localRing.status` | {identity} · worker {worker} · 實體設備未驗證 | {identity} · worker {worker} · physical device not verified | index.html (script) |
| `localRing.cmd.queued` | 已入列，尚未執行 | Queued, not executed yet | index.html (script) |
| `localRing.cmd.applying` | 執行中，尚無回覆 | Executing, no reply yet | index.html (script) |
| `localRing.cmd.executed_in_simulator` | 模擬執行完成，非實體回報 | Simulated execution done, not a physical report | index.html (script) |
| `localRing.cmd.execution_unconfirmed` | 缺少執行 ACK，結果未確認 | Execution ACK missing, result unconfirmed | index.html (script) |
| `localRing.cmd.denied` | 授權檢查拒絕 | Denied by authorization check | index.html (script) |
| `localRing.cmd.expired` | 命令已過期 | Command expired | index.html (script) |
| `localRing.cmd.unmatched` | 缺少匹配回覆，結果未確認 | No matching reply, result unconfirmed | index.html (script) |
| `localRing.cmd.unknown` | 尚未確認 | Not confirmed yet | index.html (script) |
| `localRing.cmd.row` | {label} · 命令 {commandId} · 請求 {requestId} | {label} · command {commandId} · request {requestId} | index.html (script) |
| `ring.heading` | Ring 官方裝置探索 · 唯讀 | Ring official device discovery · read-only | index.html |
| `ring.intro` | 先登入並填好本機操作碼，再到 Playground 複製新權杖；回來直接按「從本機剪貼簿匯入」，中途不要複製其他內容。本頁不會讀取或接收權杖內容；匯入後需再次輸入操作碼並手動查詢。查詢只顯示去識別數量，不會配對或控制下方七個模擬設備。本機獨立操作碼不是手機雙因素認證。 | Log in and fill in the local operator code first, then copy a new token in the Playground; come back and press "Import token from local clipboard" without copying anything else in between. This page never reads or receives the token; after import, enter the operator code again and query manually. Queries only show de-identified counts and never pair or control the seven simulated devices below. The local independent operator code is not phone two-factor authentication. | index.html |
| `ring.operator.label` | 本機獨立操作碼 | Local independent operator code | index.html |
| `ring.operator.hint` | 由啟動伺服器的 Terminal 顯示；不要在此輸入 Ring 權杖。 | Shown in the Terminal that started the server; do not enter a Ring token here. | index.html |
| `ring.import` | 從本機剪貼簿匯入權杖 | Import token from local clipboard | index.html |
| `ring.discover` | 手動查詢 Ring 裝置 | Query Ring devices manually | index.html |
| `ring.diag.initial` | 目前輸入 0 字。尚未送出操作碼；輸入字數不代表驗證通過。此處只保留字數與時間，不保留操作碼內容。 | Current input: 0 chars. No operator code sent yet; the character count does not mean verification passed. Only length and time are kept here, never the operator code. | index.html |
| `ring.import.initial` | 尚未從本機剪貼簿匯入 Ring 權杖。 | No Ring token imported from the local clipboard yet. | index.html, index.html (script) |
| `ring.discovery.initial` | 尚未查詢 Ring 官方 API。 | Ring official API not queried yet. | index.html, index.html (script) |
| `ring.capture` | 擷取 Ring 候選回執 | Capture Ring candidate receipt | index.html |
| `ring.capture.initial` | 尚未擷取回執；影片及人工驗收尚未完成。 | No receipt captured; video and manual acceptance not done yet. | index.html |
| `ring.historyDevice.label` | Ring 裝置序號 | Ring device ordinal | index.html |
| `ring.historyDevice.queryFirst` | 先手動查詢裝置 | Query devices manually first | index.html, index.html (script) |
| `ring.historyDevice.choose` | 選擇裝置序號 | Choose a device ordinal | index.html (script) |
| `ring.historyDevice.item` | Ring 裝置 {n} | Ring device {n} | index.html (script) |
| `ring.historyDevice.hint` | 僅顯示序號，不會顯示官方裝置 ID。 | Only ordinals are shown, never official device IDs. | index.html |
| `ring.history` | 手動查詢 Motion 紀錄（唯讀） | Query Motion history manually (read-only) | index.html |
| `ring.history.initial` | 尚未探測 Ring Event History 權限；此查詢不會觸發裝置動作。 | Ring Event History permission not probed yet; this query does not trigger any device action. | index.html, index.html (script) |
| `ring.diag.op.NONE` | 尚無 | none | index.html (script) (dynamic `ring.diag.op.*`) |
| `ring.diag.op.IMPORT` | 匯入權杖 | import token | index.html (script) (dynamic `ring.diag.op.*`) |
| `ring.diag.op.DISCOVERY` | 查詢裝置 | query devices | index.html (script) (dynamic `ring.diag.op.*`) |
| `ring.diag.op.HISTORY` | 查詢 Motion 紀錄 | query Motion history | index.html (script) (dynamic `ring.diag.op.*`) |
| `ring.diag.op.CAPTURE` | 擷取候選回執 | capture candidate receipt | index.html (script) (dynamic `ring.diag.op.*`) |
| `ring.diag.gate.NOT_CHECKED` | 尚未驗證 | not verified yet | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.PENDING` | 等待驗證 | awaiting verification | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.PASSED` | 本機操作碼已通過 | local operator code passed | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.DENIED` | 本機操作碼未通過 | local operator code denied | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.UNAVAILABLE` | 本機操作碼尚未設定 | local operator code not configured | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.LIMITED` | 需稍後再試 | retry later | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.gate.UNKNOWN` | 尚無驗證結論 | no verification verdict | index.html (script) (dynamic `ring.diag.gate.*`) |
| `ring.diag.phase.IDLE` | 尚未送出 | not sent yet | index.html (script) (dynamic `ring.diag.phase.*`) |
| `ring.diag.phase.NOT_SENT` | 未送出 | not sent | index.html (script) (dynamic `ring.diag.phase.*`) |
| `ring.diag.phase.SENDING` | 等待回應 | awaiting response | index.html (script) (dynamic `ring.diag.phase.*`) |
| `ring.diag.phase.COMPLETE` | 已收到回應 | response received | index.html (script) (dynamic `ring.diag.phase.*`) |
| `ring.diag.outcome.LOCAL_IMPORT_OK` | 匯入完成，尚未查證 Ring 權杖 | import done, Ring token not verified yet | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_OK` | 裝置查詢完成，未執行裝置動作 | device query done, no device action executed | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.HISTORY_OK` | 紀錄查詢完成，未執行裝置動作 | history query done, no device action executed | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.CAPTURE_PENDING` | 候選回執已保存，待影片及人工驗收 | candidate receipt saved, awaiting video and manual acceptance | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_HTTP_401` | Ring 未接受這次授權（401） | Ring did not accept this authorization (401) | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_HTTP_403` | Ring 拒絕這次存取（403） | Ring refused this access (403) | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_TIMEOUT` | Ring 查詢逾時 | Ring query timed out | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_NETWORK_ERROR` | 無法連線至 Ring | Cannot connect to Ring | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.DISCOVERY_NOT_SUCCESSFUL` | Ring 回應格式不符或查詢未完成 | Ring response malformed or query not completed | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.INPUT_EMPTY` | 請先輸入本機獨立操作碼 | Enter the local independent operator code first | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.NOT_STARTED` | 尚無結果 | no result yet | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.PENDING` | 處理中 | in progress | index.html (script) (dynamic `ring.diag.outcome.*`) |
| `ring.diag.outcome.fallback` | 未完成 | not completed | index.html (script) |
| `ring.diag.none` | 尚無 | none | index.html (script) |
| `ring.diag.whitespace` | （含空白） |  (contains whitespace) | index.html (script) |
| `ring.diag.sent` | {length} 字，時間：{at} | {length} chars at {at} | index.html (script) |
| `ring.diag.notSent` | 尚未送出請求 | no request sent yet | index.html (script) |
| `ring.diag.text` | 目前輸入 {length} 字{whitespace}；最後輸入：{inputAt}。上一筆操作：{operation}；上一筆送出：{sent}；上一筆清空：{clearedAt}；上一筆進度：{phase}。上一筆本機門禁：{gate}；上一筆步驟：{outcome}（{code}）。目前輸入字數不代表驗證通過；不保留操作碼內容。 | Current input: {length} chars{whitespace}; last input: {inputAt}. Last operation: {operation}; last submit: {sent}; last cleared: {clearedAt}; last progress: {phase}. Last local gate: {gate}; last step: {outcome} ({code}). The current character count does not mean verification passed; the operator code is never kept. | index.html (script) |
| `ring.err.operatorUnavailable` | 本機獨立操作碼尚未設定或設定無效。 | The local independent operator code is not configured or invalid. | index.html (script) |
| `ring.err.operatorDenied` | 本機獨立操作碼未通過驗證。 | The local independent operator code was not accepted. | index.html (script) |
| `ring.err.operatorRateLimit` | 操作碼失敗次數過多，請稍後再試。 | Too many failed operator code attempts; try again later. | index.html (script) |
| `ring.err.clipboardUnavailable` | 本機剪貼簿目前無法讀取。 | The local clipboard cannot be read right now. | index.html (script) |
| `ring.import.needOperator` | 請先輸入本機獨立操作碼；尚未送出匯入請求。 | Enter the local independent operator code first; no import request sent. | index.html (script) |
| `ring.import.running` | 正在從本機剪貼簿匯入，尚未完成。 | Importing from the local clipboard, not finished yet. | index.html (script) |
| `ring.import.done` | 權杖已匯入本機伺服器記憶體，頁面未接收權杖。時間：{at}。 | Token imported into local server memory; the page never received it. Time: {at}. | index.html (script) |
| `ring.import.err.busy` | 已有一筆匯入正在進行。 | An import is already in progress. | index.html (script) |
| `ring.import.err.tokenInvalid` | 剪貼簿不是單獨的 Ring 權杖；請重新複製新權杖。 | The clipboard does not hold a single Ring token; copy a new token again. | index.html (script) |
| `ring.import.err.fallback` | 本機匯入未完成。 | Local import not completed. | index.html (script) |
| `ring.import.failed` | Ring 權杖未匯入：{reason} | Ring token not imported: {reason} | index.html (script) |
| `ring.discovery.afterImport` | 尚未查詢 Ring 官方 API；請再次輸入本機獨立操作碼後手動查詢。 | Ring official API not queried yet; enter the local independent operator code again and query manually. | index.html (script) |
| `ring.discovery.needOperator` | 請先輸入本機獨立操作碼；尚未送出裝置查詢。 | Enter the local independent operator code first; no device query sent. | index.html (script) |
| `ring.discovery.running` | 正在查詢 Ring 官方 API，尚未取得結果。 | Querying the Ring official API, no result yet. | index.html (script) |
| `ring.discovery.done` | Ring 官方探索完成：{count} 個裝置（唯讀、未配對、未執行動作）。查詢時間：{at}。 | Ring official discovery done: {count} device(s) (read-only, not paired, no action executed). Queried at: {at}. | index.html (script) |
| `ring.discovery.err.busy` | 已有一筆 Ring 查詢正在進行。 | A Ring query is already in progress. | index.html (script) |
| `ring.discovery.err.tokenUnavailable` | 本機伺服器尚未取得 Ring Playground 權杖。 | The local server has no Ring Playground token yet. | index.html (script) |
| `ring.discovery.err.tokenInvalid` | 本機伺服器的 Ring Playground 權杖格式無效。 | The local server’s Ring Playground token format is invalid. | index.html (script) |
| `ring.discovery.err.fallback` | 官方服務或連線未能完成查詢。 | The official service or connection could not complete the query. | index.html (script) |
| `ring.discovery.failed` | Ring 官方探索未完成：{reason}未配對或執行任何裝置動作。 | Ring official discovery not completed: {reason} No device was paired or operated. | index.html (script) |
| `ring.history.needDiscovery` | 請先完成裝置探索，才能選擇序號探測 History。 | Finish device discovery first, then choose an ordinal to probe History. | index.html (script) |
| `ring.capture.needOperator` | 請先輸入本機獨立操作碼；尚未送出擷取請求。 | Enter the local independent operator code first; no capture request sent. | index.html (script) |
| `ring.capture.running` | 正在擷取候選回執，尚未完成。 | Capturing candidate receipt, not finished yet. | index.html (script) |
| `ring.capture.done` | 候選回執：{receiptId}；{count} 個裝置；{at}。影片及人工驗收尚未完成。 | Candidate receipt: {receiptId}; {count} device(s); {at}. Video and manual acceptance not done yet. | index.html (script) |
| `ring.capture.err.DISCOVERY_HTTP_401` | Ring 未接受這次授權（401）；請確認權杖後重新匯入。尚未保存候選回執。 | Ring did not accept this authorization (401); check the token and import again. No candidate receipt saved. | index.html (script) |
| `ring.capture.err.DISCOVERY_HTTP_403` | Ring 拒絕這次存取（403）；請確認 App 的存取權限。尚未保存候選回執。 | Ring refused this access (403); check the app’s access permissions. No candidate receipt saved. | index.html (script) |
| `ring.capture.err.DISCOVERY_TIMEOUT` | Ring 查詢逾時；尚未保存候選回執。 | Ring query timed out; no candidate receipt saved. | index.html (script) |
| `ring.capture.err.DISCOVERY_NETWORK_ERROR` | 無法連線至 Ring；尚未保存候選回執。 | Cannot connect to Ring; no candidate receipt saved. | index.html (script) |
| `ring.capture.err.DISCOVERY_NOT_SUCCESSFUL` | Ring 回應格式不符或查詢未完成；尚未保存候選回執。 | Ring response malformed or query not completed; no candidate receipt saved. | index.html (script) |
| `ring.capture.err.RECEIPT_PUBLISH_OUTCOME_UNKNOWN` | 回執發布結果未知，請先讀回確認；不要自動重試。 | Receipt publish outcome unknown; read it back first and do not retry automatically. | index.html (script) |
| `ring.capture.err.fallback` | 候選回執未完成，請確認登入、本機操作碼及匯入狀態。 | Candidate receipt not completed; check login, local operator code and import status. | index.html (script) |
| `ring.history.needDevice` | 請先探索 Ring 裝置並選擇有效序號。 | Discover Ring devices first and choose a valid ordinal. | index.html (script) |
| `ring.history.needOperator` | 請先輸入本機獨立操作碼；尚未送出紀錄查詢。 | Enter the local independent operator code first; no history query sent. | index.html (script) |
| `ring.history.running` | 正在唯讀查詢官方 Event History；尚未取得結果。 | Querying the official Event History read-only; no result yet. | index.html (script) |
| `ring.history.latest` | ；最近一筆：{at} | ; latest: {at} | index.html (script) |
| `ring.history.done` | 官方 Motion 歷史首批回傳 {count} 筆{latest}。只完成唯讀能力探測；未配對、開燈或控制實體裝置。 | Official Motion history first page returned {count} item(s){latest}. Read-only capability probe only; nothing was paired, no light turned on, no physical device controlled. | index.html (script) |
| `ring.history.err.busy` | 已有一筆 History 查詢正在進行。 | A History query is already in progress. | index.html (script) |
| `ring.history.err.tokenUnavailable` | 本機伺服器尚未取得 Ring 權杖。 | The local server has no Ring token yet. | index.html (script) |
| `ring.history.err.tokenInvalid` | 本機 Ring 權杖格式無效。 | The local Ring token format is invalid. | index.html (script) |
| `ring.history.err.http401` | 官方拒絕此權杖，可能已過期。 | The official API rejected this token; it may have expired. | index.html (script) |
| `ring.history.err.http403` | 官方未授權此裝置的 History 權限。 | The official API has not granted History permission for this device. | index.html (script) |
| `ring.history.err.http404` | 官方無法提供此裝置的 History。 | The official API cannot provide History for this device. | index.html (script) |
| `ring.history.err.deviceNotFound` | 此裝置序號已失效，請重新探索。 | This device ordinal is no longer valid; discover again. | index.html (script) |
| `ring.history.err.fallback` | 官方服務或回應未通過驗證。 | The official service or response failed validation. | index.html (script) |
| `ring.history.failed` | Ring History 探測未完成：{reason}未執行任何裝置動作。 | Ring History probe not completed: {reason} No device action was executed. | index.html (script) |
| `cloud.heading` | 雲端 MCP（AWS）實機鏈 | Cloud MCP (AWS) live chain | index.html |
| `cloud.label.ring` | Ring 側：Playground 沙盒 | Ring side: Playground sandbox | index.html |
| `cloud.label.mac` | Mac 端：software-direct（簡化保證） | Mac side: software-direct (reduced assurance) | index.html |
| `cloud.intro` | 這一區會真的呼叫 AWS 雲端 MCP：Cognito 登入 → software_test_switch.set → 本機 Mac worker 取件、驗簽、執行軟體開關、回執 → software_test_switch.result。本機獨立操作碼只在每次雲端登入時輸入一次；之後的動作沿用這次登入，直到權杖過期（約 5 分鐘）。Mac 金鑰密語只在啟動伺服器時於 Terminal 隱藏輸入一次，不經過瀏覽器、也不放進環境變數。登入網址不會自動開啟；回呼網址送出後只存在本機伺服器記憶體，由第一個動作使用；換到的權杖也只留在伺服器記憶體。軟體開關是記憶體內測試開關，不是實體裝置。同一條鏈也能送出 home_device.command（對已配對的模擬設備執行一個允許清單內的動作）→ home_device.result。 | This section makes real calls to the AWS cloud MCP: Cognito login → software_test_switch.set → the local Mac worker fetches, verifies the signature, executes the software switch and sends a receipt → software_test_switch.result. The local independent operator code is asked once per cloud login; later actions reuse that login until its token expires (about 5 minutes). The Mac key passphrase is typed once, hidden, in the Terminal when the server starts; it never passes through the browser or an environment variable. The login URL is never opened automatically; a submitted callback URL lives only in local server memory and is spent by the first action; the resulting token stays in server memory only. The software switch is an in-memory test switch, not a physical device. The same chain can also send home_device.command (one allowlisted action on a paired SIMULATED device) → home_device.result. | index.html |
| `guardian.heading` | Ring 居家守護 | Ring home guardian | index.html |
| `guardian.loading` | 檢查中… | Checking… | index.html |
| `guardian.allGood` | 一切正常 | All normal | guardian.mjs |
| `guardian.attention` | 有 {n} 件事要注意 | {n} things need attention | guardian.mjs |
| `guardian.attentionOne` | 有 1 件事要注意 | 1 thing needs attention | guardian.mjs |
| `guardian.hubUnreachable` | 主機連不上 | The home hub is not answering | guardian.mjs |
| `guardian.clock` | 家中時間 {time} | Home time {time} | guardian.mjs |
| `guardian.clockFast` | 家中時間 {time}（展示時鐘 ×{speed}） | Home time {time} (demo clock ×{speed}) | guardian.mjs |
| `guardian.target.camera` | Ring 攝影機 | Ring camera | index.html |
| `guardian.target.gateway` | 家中閘道 | Home gateway | index.html |
| `guardian.routineLabel` | 今日作息完成 | Today's routine done | index.html |
| `guardian.state.online` | 在線 | Online | guardian.mjs (dynamic `guardian.state.*`) |
| `guardian.state.late` | 心跳延遲 | Heartbeat late | guardian.mjs (dynamic `guardian.state.*`) |
| `guardian.state.offline` | 斷線 | Offline | guardian.mjs (dynamic `guardian.state.*`) |
| `guardian.cameraRing` | Ring 實際狀態 · 最後 {last} | Ring status · last {last} | guardian.mjs |
| `guardian.cameraSim` | 模擬 · 最後 {last} | SIMULATED · last {last} | guardian.mjs |
| `guardian.gatewayNote` | 模擬 · 最後 {last} | SIMULATED · last {last} | guardian.mjs |
| `guardian.gatewayNoteUsb` | 真的 ESP32-C3（USB）· 最後 {last} | Real ESP32-C3 on USB · last {last} | guardian.mjs |
| `guardian.target.home_button` | 家中按鈕 | Home button | guardian.mjs (dynamic `guardian.target.*`) |
| `guardian.email.enabled` | Email 通知：已開啟（Amazon SNS） | Email alerts: on (Amazon SNS) | guardian.mjs (dynamic `guardian.email.*`) |
| `guardian.email.disabled` | Email 通知：未啟用，只在本頁顯示 | Email alerts: off; alerts show on this page only | guardian.mjs (dynamic `guardian.email.*`) |
| `guardian.email.error` | Email 通知：上一封沒有寄出 | Email alerts: the last email could not be sent | guardian.mjs (dynamic `guardian.email.*`) |
| `guardian.email.misconfigured` | Email 通知：設定有誤 | Email alerts: settings are invalid | guardian.mjs (dynamic `guardian.email.*`) |
| `guardian.todayHeading` | 今日作息 | Today's routine | index.html |
| `guardian.eventsHeading` | 時間軸 | Timeline | index.html |
| `guardian.noEvents` | 目前沒有狀態變化。 | Nothing has changed yet. | guardian.mjs |
| `guardian.result.pending` | 等待中 | waiting | guardian.mjs (dynamic `guardian.result.*`) |
| `guardian.result.confirmed` | ✓ 已確認 | ✓ confirmed | guardian.mjs (dynamic `guardian.result.*`) |
| `guardian.result.not_executed` | ✗ 未執行 | ✗ not done | guardian.mjs (dynamic `guardian.result.*`) |
| `guardian.result.unknown` | ? 無法確認 | ? cannot confirm | guardian.mjs (dynamic `guardian.result.*`) |
| `guardian.result.not_monitored` | – 監看開始前 | – before monitoring started | guardian.mjs (dynamic `guardian.result.*`) |
| `guardian.retry` | 現在補做 | Do it now | guardian.mjs |
| `guardian.retryFailed` | 未完成（{reason}）。 | Not completed ({reason}). | guardian.mjs |
| `guardian.event.offline` | {target}斷線（最後心跳 {last}） | {target} offline (last heartbeat {last}) | guardian.mjs |
| `guardian.event.late` | {target}心跳延遲（最後 {last}） | {target} heartbeat late (last {last}) | guardian.mjs |
| `guardian.event.recovered` | {target}已恢復 | {target} back online | guardian.mjs |
| `guardian.event.ok` | {target}心跳恢復正常 | {target} heartbeat normal again | guardian.mjs |
| `guardian.event.routineDone` | {at} {target}{action} ✓ | {at} {target} {action} ✓ | guardian.mjs |
| `guardian.event.routineMissed` | {at} {target}{action}沒有完成（{reason}） | {at} {target} {action} not done ({reason}) | guardian.mjs |
| `guardian.event.ringLive` | Ring 攝影機：改用 Ring 實際狀態 | Ring camera: using real Ring status | guardian.mjs |
| `guardian.event.ringToken` | Ring token 已過期；重新載入前攝影機改用模擬 | Ring token expired; camera is simulated until a new token is loaded | guardian.mjs |
| `guardian.event.doorRequested` | 「{who}」請求開前門 | "{who}" asked to open the front door | guardian.mjs |
| `guardian.event.doorApproved` | 前門已開（模擬）：申請者「{who}」，核准者「{by}」✓ 收據 {receipt} | Front door opened for "{who}", approved by "{by}" (SIMULATED) ✓ receipt {receipt} | guardian.mjs |
| `guardian.event.doorDenied` | 「{who}」的開門請求被「{by}」拒絕 | Door request from "{who}" denied by "{by}" | guardian.mjs |
| `guardian.event.doorExpired` | 「{who}」的開門請求逾時（60 秒內無人處理） | Door request from "{who}" expired (no decision in 60 s) | guardian.mjs |
| `guardian.event.doorbellAgain` | 有人又按了一次 Ring 門鈴（已有開門請求在等待） | The Ring doorbell was pressed again while a door request was waiting | guardian.mjs |
| `guardian.event.doorFailed` | 已核准但門沒有開（{reason}） | Door approved but NOT opened ({reason}) | guardian.mjs |
| `door.pending` | 「{who}」請求開前門 — 剩 {seconds} 秒 | "{who}" asks to open the front door — {seconds} s left | door.mjs |
| `door.via.mcp` | AI 代理（MCP） | AI agent over MCP | door.mjs (dynamic `door.via.*`), guardian.mjs (dynamic `door.via.*`) |
| `door.via.phone` | 家人手機 | family phone | door.mjs (dynamic `door.via.*`), guardian.mjs (dynamic `door.via.*`) |
| `door.via.ring` | Ring 門鈴 | Ring doorbell | door.mjs (dynamic `door.via.*`), guardian.mjs (dynamic `door.via.*`) |
| `door.pendingPerson` | Ring 偵測到門口有人 — 要開門嗎？剩 {seconds} 秒 | Ring sees a person at the front door — open the door? {seconds} s left | door.mjs |
| `door.pendingRing` | 有人按了 Ring 門鈴 — 要開門嗎？剩 {seconds} 秒 | Someone rang the Ring doorbell — open the door? {seconds} s left | door.mjs |
| `guardian.simDoorbell` | 展示：模擬按 Ring 門鈴 | Demo: ring the doorbell | index.html |
| `guardian.simVacuumStuck` | 展示：掃地機卡住 | Demo: vacuum gets stuck | index.html |
| `guardian.event.parentOk` | 家中按鈕被按了一下：「我很好」 | The home button was pressed: "I'm OK" | guardian.mjs |
| `guardian.event.parentHelp` | 家中按鈕被長按：需要幫忙，已寄信通知家人 | The home button was held down: help requested, family emailed | guardian.mjs |
| `guardian.event.vacuumStarted` | 掃地機開始打掃（{origin}） | Robot vacuum started ({origin}) | guardian.mjs |
| `guardian.event.vacuumDone` | 掃地機掃完 {minutes} 分鐘，已回充電座（收據 {receipt}） | Robot vacuum finished after {minutes} min and is back on the dock (receipt {receipt}) | guardian.mjs |
| `guardian.event.vacuumStuck` | 掃地機停住了（{reason}），已掃 {minutes} 分鐘；已寄信通知家人 | Robot vacuum stopped ({reason}) after {minutes} min; family emailed | guardian.mjs |
| `guardian.event.vacuumUnknown` | 無法確認掃地機是否掃完（{reason}） | Robot vacuum finish cannot be confirmed ({reason}) | guardian.mjs |
| `guardian.event.agentRefused` | AI 代理要求 {target} {action}，已拒絕（{reason}） | An AI agent asked for {target} {action}; refused ({reason}) | guardian.mjs |
| `careNote.send` | 寄出今天的照護摘要 | Send today's care note | index.html |
| `careNote.writing` | 正在根據今天的紀錄撰寫… | Writing from today's log… | guardian.mjs |
| `careNote.fromBedrock` | 由 Amazon Bedrock（Claude）只根據今天的紀錄撰寫。 | Written by Amazon Bedrock (Claude) from today's log only. | guardian.mjs |
| `careNote.fromTemplate` | 固定範本摘要（未使用 Bedrock：{reason}）。 | Plain summary (Bedrock not used: {reason}). | guardian.mjs |
| `careNote.emailed` | 已寄給家人。 | Emailed to the family. | guardian.mjs |
| `careNote.notEmailed` | 未設定 Email。 | Email not configured. | guardian.mjs |
| `door.via.console` | 控制台 | this console | door.mjs (dynamic `door.via.*`), guardian.mjs (dynamic `door.via.*`) |
| `door.approve` | 核准 | Approve | index.html |
| `door.liveStart` | Ring 即時影像 | Ring live view | door.mjs, index.html |
| `door.liveStop` | 停止即時影像 | Stop live view | door.mjs |
| `door.liveConnecting` | 正在連線 Ring 攝影機… | Connecting to the Ring camera… | door.mjs |
| `door.liveOn` | Ring 攝影機即時畫面（不錄影；決定後即結束）。 | Live from the Ring camera (not recorded; ends when you decide). | door.mjs |
| `door.liveEnded` | 即時影像已結束（Ring 時間上限）。可再按一次重新連線。 | Live view ended (Ring time limit). Tap again to reconnect. | door.mjs |
| `door.liveFailed` | 即時影像暫時無法使用（{reason}）。上面的快照仍可用。 | Live view not available ({reason}). The snapshot above still works. | door.mjs |
| `door.deny` | 拒絕 | Deny | index.html |
| `door.simulatedNote` | 模擬門鎖。由這支管理員手機決定（或已開通遠端核准的手機）；AI 代理只能申請。 | SIMULATED door. This admin phone decides (or a phone enabled for remote approval); the AI agent can only ask. | index.html |
| `door.snapshotAlt` | 門口快照 | Front door snapshot | door.mjs |
| `door.snapshotRing` | Ring 門口快照（只在記憶體，決定後即刪除）。 | Ring door snapshot (memory only, gone after you decide). | door.mjs |
| `door.snapshotSim` | 沒有 Ring 影像（{reason}）；顯示模擬圖。 | No Ring image ({reason}); showing a SIMULATED stand-in. | door.mjs |
| `door.snapshotNoImage` | Ring 目前還沒有影像。按「Ring 即時影像」，開始幾秒後快照會自動更新。 | Ring has no recent image yet. Tap Ring live view; the snapshot updates a few seconds after it starts. | door.mjs |
| `door.snapshotLoading` | 正在取得門口快照… | Getting the door snapshot… | door.mjs |
| `door.asked` | 已送出開門請求（模擬），等待管理員手機核准（{seconds} 秒）。 | Door request sent (SIMULATED). Waiting for the admin phone to approve ({seconds} s). | index.html (script) |
| `door.mine.pending` | 你的開門請求：等待管理員核准（{seconds} 秒） | Your door request: waiting for the admin ({seconds} s) | door.mjs |
| `door.mine.approved` | 你的開門請求已由「{by}」核准 — 門已開（模擬）。 | Your door request was approved by "{by}" — door opened (SIMULATED). | door.mjs (dynamic `door.mine.*`) |
| `door.mine.denied` | 你的開門請求被拒絕。 | Your door request was denied. | door.mjs (dynamic `door.mine.*`) |
| `door.mine.expired` | 你的開門請求逾時，60 秒內無人處理。 | Your door request expired; nobody decided within 60 s. | door.mjs (dynamic `door.mine.*`) |
| `door.mine.failed` | 已核准，但門沒有開（{reason}）。 | Approved, but the door did not open ({reason}). | door.mjs (dynamic `door.mine.*`) |
| `door.decided.approved` | 已核准 — 門已開（模擬），收據 {receipt}。 | Approved — door opened (SIMULATED), receipt {receipt}. | door.mjs (dynamic `door.decided.*`) |
| `door.decided.denied` | 已拒絕 — 門維持上鎖。 | Denied — the door stays locked. | door.mjs (dynamic `door.decided.*`) |
| `door.decided.failed` | 已核准，但門沒有開（{reason}）。 | Approved, but the door did not open ({reason}). | door.mjs (dynamic `door.decided.*`) |
| `faceHint.pending` | 人臉提示：比對中… | Face hint: checking… | door.mjs |
| `faceHint.looksLike` | 人臉提示：看起來像「{name}」（{score}）— 只是提示，由你決定 | Face hint: looks like {name} ({score}) — a hint only, you decide | door.mjs, faces.mjs |
| `faceHint.notEnrolled` | 人臉提示：未登錄的人 | Face hint: a person who is not enrolled | door.mjs, faces.mjs |
| `faceHint.no_face` | 人臉提示：快照中沒有臉 | Face hint: no face in the snapshot | door.mjs (dynamic `faceHint.*`), faces.mjs (dynamic `faceHint.*`) |
| `faceHint.no_image` | 人臉提示：沒有 Ring 影像可比對 | Face hint: no Ring image to check | door.mjs (dynamic `faceHint.*`), faces.mjs (dynamic `faceHint.*`) |
| `faceHint.disabled` | 人臉提示未啟用 | Face hint is off | door.mjs (dynamic `faceHint.*`), faces.mjs (dynamic `faceHint.*`) |
| `faceHint.error` | 這次無法提供人臉提示 | Face hint unavailable this time | door.mjs (dynamic `faceHint.*`), faces.mjs (dynamic `faceHint.*`) |
| `ringConnect.heading` | Ring 連線 | Ring connection | index.html |
| `ringConnect.intro` | token 只存在這台 Mac 的記憶體，不會再顯示。過期後 Ring 改為模擬，直到你貼上新的。 | The token stays in this Mac's memory only and is never shown again. When it expires, Ring switches to simulated until you paste a new one. | index.html |
| `ringConnect.step1` | 向 Ring 取得 token（有效 30 分鐘） | Get a token from Ring (valid 30 minutes) | index.html |
| `ringConnect.step2` | 複製後貼到這裡 | Copy it, then paste here | index.html |
| `ringConnect.step3` | 連線 | Connect | index.html |
| `ringConnect.pasteButton` | 從剪貼簿貼上 | Paste from clipboard | index.html |
| `ringConnect.pasted` | 已貼上（不顯示），請按「連線」。 | Pasted (hidden). Press Connect. | ring-connect.mjs |
| `ringConnect.pasteBlocked` | 這個瀏覽器不允許直接貼上；請長按欄位再貼上。 | This browser did not allow pasting; long-press the field and paste instead. | ring-connect.mjs |
| `ringConnect.open` | 打開 Ring Playground | Open Ring Playground | index.html |
| `ringConnect.paste` | 貼上 token（不顯示） | Paste the token (hidden) | index.html |
| `ringConnect.connect` | 連線 | Connect | index.html |
| `ringConnect.disconnect` | 中斷 | Disconnect | index.html |
| `remote.heading` | 遠端核准 | Remote approval | index.html |
| `remote.intro` | 不在家也能回覆開門申請。每支手機自己產生金鑰；雲端只負責傳話，這台主機先驗手機簽章才會開門。 | Answer door requests when you are away. Each phone makes its own key; the cloud only passes messages, and this hub checks the phone's signature before anything opens. | index.html |
| `remote.enable` | 開啟遠端核准 | Enable remote approval | index.html |
| `remote.open` | 在這支手機開啟 | Open on this phone | index.html |
| `remote.copy` | 複製連結給家人手機 | Copy link for a family phone | index.html |
| `remote.code` | 一次性代碼 {code}，{min} 分鐘內有效。在要回覆的手機上開啟連結。 | One-time code {code}, valid {min} minutes. Open the link on the phone that should answer. | remote-approval.mjs |
| `remote.off` | 這台主機未設定 | Not set up on this hub | remote-approval.mjs |
| `remote.none` | 尚無手機開通 | No phone enabled | remote-approval.mjs |
| `remote.on` | 已開通 {n} 支手機 | {n} phone(s) enabled | remote-approval.mjs |
| `remote.remove` | 移除 | Remove | remote-approval.mjs |
| `remote.removed` | 已移除，那支手機不能再回覆。 | Removed. That phone can no longer answer. | remote-approval.mjs |
| `remote.copied` | 已複製。請私下傳送，只能用一次。 | Link copied. Send it privately; it works once. | remote-approval.mjs |
| `remote.copyBlocked` | 瀏覽器不允許複製，請改用「在這支手機開啟」。 | Copy blocked by the browser; use Open on this phone. | remote-approval.mjs |
| `remote.unreachable` | 暫時連不到中繼，請在家用這支手機回覆。 | Relay not reachable right now; answer at home on this phone. | remote-approval.mjs |
| `remote.failed` | 未完成（{reason}）。 | Not done ({reason}). | remote-approval.mjs |
| `ringConnect.none` | 模擬中 · 沒有 token | Simulated · no token | ring-connect.mjs |
| `ringConnect.live` | 已連線 · 約剩 {min} 分鐘 | Live · about {min} min left | ring-connect.mjs |
| `ringConnect.liveOver` | 已連線 · 已超過 30 分鐘，可能快過期 | Live · past 30 min, may expire soon | ring-connect.mjs |
| `ringConnect.expired` | 已過期 · 請貼新的 token | Expired · paste a new token | ring-connect.mjs |
| `ringConnect.offline` | 此主機已關閉 Ring 連線 | Off on this hub | ring-connect.mjs |
| `ringConnect.saved` | 已載入記憶體，欄位已清空。 | Token loaded into memory. The field was cleared. | ring-connect.mjs |
| `ringConnect.cleared` | 已從記憶體移除。 | Token removed from memory. | ring-connect.mjs |
| `ringConnect.unreachable` | 連不到主機，所以什麼都沒送出。請確認手機和 Mac 的連線後再貼一次。 | Could not reach the hub, so nothing was sent. Check the phone's connection to the Mac and paste again. | ring-connect.mjs |
| `ringConnect.failed` | 未完成（{reason}）。 | Not done ({reason}). | ring-connect.mjs |
| `faces.heading` | 人臉提示（選用） | Face hints (optional) | index.html |
| `faces.intro` | 登錄常來的人（例如照服員），必須經本人同意。主機只在這台 Mac 存加密的人臉特徵，不存照片。提示只出現在你的開門核准畫面，絕不會自動開門。 | Enrol people who often come to the door (e.g. the carer), only with their consent. The hub keeps an encrypted face feature on this Mac, never the photo. The hint appears on your door approval screen only and never opens the door. | index.html |
| `faces.name` | 名字 | Name | index.html |
| `faces.photo` | 照片（只有一張臉） | Photo with one face | index.html |
| `faces.consent` | 此人已同意登錄作為開門提示，並知道隨時可要求刪除。 | This person agreed to be enrolled for door hints and knows they can ask to be deleted at any time. | index.html |
| `faces.enroll` | 登錄 | Enrol | index.html |
| `faces.check` | 用照片試比對 | Try a photo | index.html |
| `faces.delete` | 刪除 | Delete | faces.mjs |
| `faces.deleteAll` | 全部刪除 | Delete everyone | index.html |
| `faces.deleteAllConfirm` | 要刪除所有已登錄的人臉嗎？刪除後無法復原。 | Delete every enrolled face? This cannot be undone. | faces.mjs |
| `faces.item` | {name} — {at} 登錄（已記錄同意） | {name} — enrolled {at} (consent recorded) | faces.mjs |
| `faces.empty` | 尚未登錄任何人。 | Nobody enrolled. | faces.mjs |
| `faces.on` | 已啟用：登錄 {n} 人。只在這台 Mac 執行。 | On: {n} enrolled. Runs only on this Mac. | faces.mjs |
| `faces.off` | 未啟用（{reason}）。沒有它開門核准照常可用。 | Off ({reason}). Door approval works without it. | faces.mjs |
| `faces.consentNeeded` | 請先勾選本人同意。 | Tick the consent box first. | faces.mjs |
| `faces.enrolled` | 已登錄「{name}」。照片沒有保存。 | Enrolled {name}. The photo was not kept. | faces.mjs |
| `faces.deleted` | 已刪除（{n}）。 | Deleted ({n}). | faces.mjs |
| `faces.failed` | 未完成（{reason}）。 | Not done ({reason}). | faces.mjs |
| `faces.working` | 正在這台 Mac 上處理… | Working on this Mac… | faces.mjs |
| `door.decideFailed` | 沒有完成決定（{reason}）。 | Decision not taken ({reason}). | door.mjs |
| `guardian.simCameraOff` | 展示：攝影機斷線 | Demo: camera offline | index.html |
| `guardian.simCameraOn` | 展示：攝影機恢復 | Demo: camera back | index.html |
| `guardian.simGatewayOff` | 展示：閘道斷線 | Demo: gateway offline | index.html |
| `guardian.simGatewayOn` | 展示：閘道恢復 | Demo: gateway back | index.html |
| `phone.pair.heading` | 用這支手機 | Use this phone | index.html |
| `phone.pair.intro` | 用 Mac 上顯示的 8 位數配對碼配對一次。第一支（管理員）手機在 Mac 螢幕跳出的視窗按「允許」；家人手機由管理員在手機上按「允許」。之後這支手機打開就能直接用。 | Pair once with the 8-digit code shown on the Mac. The first (admin) phone is approved in a window on the Mac screen; family phones are approved on the admin phone. After that this phone opens the console directly. | index.html |
| `phone.pair.code` | 配對碼（8 位數） | Pairing code (8 digits) | index.html |
| `phone.pair.name` | 這支手機的名字 | Name for this phone | index.html |
| `phone.pair.submit` | 配對這支手機 | Pair this phone | index.html |
| `phone.pair.waiting` | 等待核准：請在 Mac 終端機輸入 y，把「{name}」配對為{role}。 | Waiting for approval: on the Mac terminal, type y to pair "{name}" as {role}. | — (not referenced: unused key) |
| `phone.pair.waitMac` | 請到 Mac 螢幕上跳出的視窗按「允許」。核對數字 {check}（Mac 上也是這組），剩 {seconds} 秒。 | Now press "Allow" in the window on the Mac screen. Check digits {check} (the Mac shows the same). {seconds} s left. | phone-pair.mjs |
| `phone.pair.waitAdmin` | 請管理員在他的手機上按「允許」。核對數字 {check}，剩 {seconds} 秒。 | Ask the admin to press "Allow" on their phone. Check digits {check}. {seconds} s left. | phone-pair.mjs |
| `pairReq.title` | 「{name}」想加入成為家人手機。核對數字 {check}（剩 {seconds} 秒） | "{name}" wants to join as a family phone. Check digits {check} ({seconds} s left) | phone-pair.mjs |
| `pairReq.note` | 請確認對方手機上顯示同一組數字。不是你認識的人，請按「拒絕」。 | Make sure their phone shows the same two digits. If you don't know this request, press Deny. | index.html |
| `pairReq.allow` | 允許 | Allow | index.html |
| `pairReq.deny` | 拒絕 | Deny | index.html |
| `pairReq.allowed` | 已把「{name}」加入成為家人手機。 | "{name}" was added as a family phone. | phone-pair.mjs |
| `pairReq.denied` | 已拒絕「{name}」的申請。 | Request from "{name}" denied. | phone-pair.mjs |
| `pairReq.failed` | 未完成（{reason}）。 | Not done ({reason}). | phone-pair.mjs |
| `phone.pair.approved` | 已核准，正在開啟控制台… | Approved. Opening the console… | phone-pair.mjs |
| `phone.pair.rejected` | Mac 拒絕了這次配對，請重新取得配對碼。 | The Mac refused this pairing. Ask for a new code. | phone-pair.mjs |
| `phone.pair.timeout` | 2 分鐘內沒有核准，請重新取得配對碼。 | No approval within 2 minutes. Ask for a new code. | phone-pair.mjs |
| `phone.pair.failed` | 配對未完成（{reason}）。 | Pairing not completed ({reason}). | phone-pair.mjs |
| `phone.unlock.button` | 用這支手機開啟 | Open with this phone | index.html |
| `phone.unlock.working` | 正在用這支手機開啟… | Opening with this phone… | phone-pair.mjs |
| `phone.unlock.failed` | 這支手機無法開啟控制台（{reason}）。若已被移除，請重新配對。 | This phone could not open the console ({reason}). Pair it again if it was removed. | phone-pair.mjs |
| `login.passcodeAlt` | 或在這台 Mac 上：展示密碼 | Or, on this Mac: demo passcode | index.html |
| `notice.phoneLoggedIn` | 已用配對手機「{name}」開啟。所有設備均為模擬。 | Opened with the paired phone "{name}". All devices are SIMULATED. | index.html (script) |
| `phones.heading` | 家人手機 | Family phones | index.html |
| `phones.intro` | 新增手機：對方畫面會出現配對碼，你在這支管理員手機按允許。手機取得信任後一直有效，直到你移除。家人可以操作日常設備、也可以申請開門；只有這支管理員手機能核准。 | Add a phone: it shows a pairing code, and you allow it here on this admin phone. Each phone stays trusted until you remove it. Family members run everyday devices and may ask to open the door; only this admin phone approves. | index.html |
| `phones.addMember` | 新增家人手機 | Add a family phone | index.html |
| `phones.addAdmin` | 新增管理員手機 | Add an admin phone | index.html |
| `phones.code` | 配對碼 {code}（{role}），{at} 前有效，只能用一次。在新手機輸入後：家人手機就在這支手機上按「允許」；管理員手機則在 Mac 跳出的視窗按「允許」。 | Pairing code {code} ({role}), valid until {at}, single use. Enter it on the new phone; family phones are then approved right here on this phone, an admin phone in the window on the Mac. | phone-pair.mjs |
| `phones.item` | {name} · {role} · 最後使用 {at} | {name} · {role} · last used {at} | phone-pair.mjs |
| `phones.empty` | 還沒有配對的手機。 | No paired phones yet. | phone-pair.mjs |
| `phones.revoke` | 移除 | Remove | phone-pair.mjs |
| `phones.revoked` | 已移除「{name}」，那支手機無法再開啟控制台。 | Removed "{name}"; that phone can no longer open the console. | phone-pair.mjs |
| `phones.failed` | 未完成（{reason}）。 | Not completed ({reason}). | phone-pair.mjs |
| `phones.roleAdmin` | 管理員 | admin | phone-pair.mjs |
| `phones.roleMember` | 家人 | family member | phone-pair.mjs |
| `cloud.introShort` | 登入一次，讓 AI 代理透過 AWS 雲端 MCP 控制已配對的模擬設備。只有這台 Mac 回傳簽名收據，指令才算完成。開門鎖、解除攝影機與數值設定永遠不接受雲端指令。 | Sign in once to let your AI agent control paired SIMULATED devices through the AWS cloud MCP. A command counts as done only after this Mac returns a signed receipt. Door unlock, camera disarm and value settings are never accepted from the cloud. | index.html |
| `cloud.callback.fold` | 完成登入：貼上回呼網址 | Finish sign-in: paste the callback URL | index.html |
| `cloud.more` | 運作方式與測試控制 | How this works and test controls | index.html |
| `fold.ring` | Ring 帳號 · 官方 API，唯讀 | Ring account · official API, read-only | index.html |
| `fold.advanced` | 進階：家庭 Wi-Fi、邊緣閘道、排程 | Advanced: home Wi-Fi, edge gateway, schedules | index.html |
| `cloud.operator.label` | 本機獨立操作碼（每次雲端登入一次） | Local independent operator code (once per cloud login) | index.html |
| `cloud.operator.hint` | 與 Ring 匯入共用同一組操作碼及失敗次數限制；送出後立即清空。 | Shares the operator code and failure limit with Ring import; cleared immediately after sending. | index.html |
| `cloud.login` | Cognito 登入 | Cognito login | index.html |
| `common.refreshStatus` | 重新整理狀態 | Refresh status | index.html |
| `cloud.status.initial` | 尚未讀取雲端 MCP 面板狀態。 | Cloud MCP panel status not read yet. | index.html |
| `cloud.login.initial` | 尚未產生 Cognito 登入網址。 | No Cognito login URL generated yet. | index.html |
| `cloud.callback.label` | 登入完成後的回呼網址（…/auth/callback?code=…&state=…） | Callback URL after login (…/auth/callback?code=…&state=…) | index.html |
| `cloud.callback.hint` | 以遮蔽方式輸入；送出後立即清空，頁面不保留。 | Masked input; cleared immediately after sending and never kept by the page. | index.html |
| `cloud.callback.submit` | 送出回呼網址 | Submit callback URL | index.html |
| `cloud.callback.clipboard` | 從本機剪貼簿讀取回呼網址 | Read callback URL from local clipboard | index.html |
| `cloud.callback.initial` | 尚未送出回呼網址。 | Callback URL not submitted yet. | cloud-mcp-panel.mjs, index.html |
| `cloud.switch.on` | 打開軟體開關 | Turn software switch ON | index.html |
| `cloud.switch.off` | 關閉軟體開關 | Turn software switch OFF | index.html |
| `cloud.result.initial` | 尚未執行雲端軟體開關。 | Cloud software switch not run yet. | index.html |
| `cloud.key.ready` | Mac 金鑰：已就緒（伺服器啟動時在 Terminal 隱藏輸入密語解鎖；密語不經瀏覽器，也不放環境變數） | Mac key: ready (unlocked by a hidden passphrase typed in the Terminal at server start; the passphrase never passes through the browser or an environment variable) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.passphrase_missing` | Mac 金鑰：未就緒（伺服器啟動時未在 Terminal 輸入密語，請用啟動腳本重新啟動） | Mac key: not ready (no passphrase typed in the Terminal at server start; restart with the start script) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.key_unlock_failed` | Mac 金鑰：未就緒（密語無法解鎖金鑰） | Mac key: not ready (the passphrase cannot unlock the key) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.key_identity_mismatch` | Mac 金鑰：未就緒（金鑰與身分紀錄不一致） | Mac key: not ready (key does not match the identity record) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.identity_missing` | Mac 金鑰：未就緒（狀態目錄沒有已登記的 Mac 身分） | Mac key: not ready (no enrolled Mac identity in the state directory) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.state_dir_missing` | Mac 金鑰：未就緒（找不到 Mac 狀態目錄） | Mac key: not ready (Mac state directory not found) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.state_dir_invalid` | Mac 金鑰：未就緒（Mac 狀態目錄權限或內容不符） | Mac key: not ready (Mac state directory permissions or contents do not match) | cloud-mcp-panel.mjs (dynamic `cloud.key.*`) |
| `cloud.key.other` | Mac 金鑰：未就緒（{key}） | Mac key: not ready ({key}) | cloud-mcp-panel.mjs |
| `cloud.key.testSource` | 【測試來源：環境變數】 |  [TEST source: environment variable] | cloud-mcp-panel.mjs |
| `cloud.status.mode` | Mac 模式：software-direct（簡化保證） | Mac mode: software-direct (reduced assurance) | cloud-mcp-panel.mjs |
| `cloud.status.loginPending` | Cognito 登入：等待回呼（{at} 前有效） | Cognito login: waiting for callback (valid until {at}) | cloud-mcp-panel.mjs |
| `cloud.status.loginIdle` | Cognito 登入：未進行或已使用 | Cognito login: not started or already used | cloud-mcp-panel.mjs |
| `cloud.status.callbackStaged` | 回呼網址：已送到本機伺服器（待使用一次） | Callback URL: sent to the local server (pending single use) | cloud-mcp-panel.mjs |
| `cloud.status.sessionActive` | 雲端登入：{at} 前有效（每個動作沿用） | Cloud login: active until {at} (reused by every action) | cloud-mcp-panel.mjs |
| `cloud.status.callbackNone` | 回呼網址：未送出 | Callback URL: not submitted | cloud-mcp-panel.mjs |
| `cloud.status.lastRun` | 上一次執行：{at} {result} | Last run: {at} {result} | cloud-mcp-panel.mjs |
| `cloud.status.lastRunOk` | 成功 | succeeded | cloud-mcp-panel.mjs |
| `cloud.status.lastRunFail` | 未成功 | not successful | cloud-mcp-panel.mjs |
| `cloud.status.separator` | ； | ;  | cloud-mcp-panel.mjs |
| `cloud.status.end` | 。 | . | cloud-mcp-panel.mjs |
| `cloud.status.error` | 雲端 MCP 面板：{reason} | Cloud MCP panel: {reason} | cloud-mcp-panel.mjs |
| `cloud.err.AUTH_REQUIRED` | 請先登入本機控制台。 | Log in to the local console first. | cloud-mcp-panel.mjs |
| `cloud.err.SESSION_EXPIRED` | 本機登入已過期，請重新登入。 | Local login expired; log in again. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CLOUD_PANEL_DISABLED` | 伺服器未啟用雲端 MCP 面板（需以啟動腳本、HOME_MCP_CLOUD_PANEL=1 啟動）。 | The server has the Cloud MCP panel disabled (start it with the start script, HOME_MCP_CLOUD_PANEL=1). | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.RING_OPERATOR_UNAVAILABLE` | 本機獨立操作碼尚未設定或設定無效。 | The local independent operator code is not configured or invalid. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.RING_OPERATOR_DENIED` | 本機獨立操作碼未通過驗證。 | The local independent operator code was not accepted. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.RING_OPERATOR_RATE_LIMIT` | 操作碼失敗次數過多，請一分鐘後再試。 | Too many failed operator code attempts; try again in one minute. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CLOUD_INTENT_REQUIRED` | 請求來源不是本頁，已拒絕。 | The request did not come from this page; refused. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CLOUD_MCP_BUSY` | 已有一筆雲端動作正在進行。 | A cloud action is already in progress. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.MAC_KEY_NOT_READY` | Mac 金鑰未就緒，無法執行。 | Mac key not ready; cannot run. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CALLBACK_URL_INVALID` | 回呼網址格式不符（只接受本部署的 /auth/callback?code=…&state=…）。 | Callback URL has the wrong shape (only this deployment’s /auth/callback?code=…&state=… is accepted). | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CALLBACK_STATE_MISMATCH` | 回呼網址不是這一次登入產生的，請重新按「Cognito 登入」。 | This callback URL is not from the current login; press "Cognito login" again. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.LOGIN_NOT_PENDING` | 目前沒有等待中的登入，請先按「Cognito 登入」。 | No login is pending; press "Cognito login" first. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.LOGIN_EXPIRED` | 登入網址已過期（10 分鐘），請重新登入。 | The login URL expired (10 minutes); log in again. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CALLBACK_NOT_STAGED` | 請先登入 Cognito；登入一次約可重複使用 5 分鐘。 | Log in to Cognito first; one login is reused for about 5 minutes. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CLIPBOARD_UNAVAILABLE` | 本機剪貼簿目前無法讀取。 | The local clipboard cannot be read right now. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.CLOUD_AUTHORIZATION_CHANGED` | 本機授權已變更，請重新操作。 | Local authorization changed; please start over. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.loginError` | Cognito 回報登入失敗，請重新登入。 | Cognito reported a login failure; log in again. | cloud-mcp-panel.mjs |
| `cloud.err.other` | 未完成（{code}）。 | Not completed ({code}). | cloud-mcp-panel.mjs |
| `cloud.needOperator` | 請先輸入本機獨立操作碼；尚未送出。 | Enter the local independent operator code first; nothing was sent. | cloud-mcp-panel.mjs |
| `cloud.login.generating` | 正在產生 Cognito 登入網址… | Generating the Cognito login URL… | cloud-mcp-panel.mjs |
| `cloud.login.link` | 在新分頁開啟 Cognito 登入頁（{host}） | Open the Cognito login page in a new tab ({host}) | cloud-mcp-panel.mjs |
| `cloud.login.after` | 　登入後複製網址列的完整回呼網址（頁面顯示錯誤屬正常），10 分鐘內有效：{at} 前。 |   After login, copy the full callback URL from the address bar (an error page there is expected). Valid for 10 minutes: until {at}. | cloud-mcp-panel.mjs |
| `cloud.login.failed` | Cognito 登入網址未產生：{reason} | Cognito login URL not generated: {reason} | cloud-mcp-panel.mjs |
| `cloud.callback.pasteFirst` | 請先貼上回呼網址。 | Paste the callback URL first. | cloud-mcp-panel.mjs |
| `cloud.callback.sourceClipboard` | 剪貼簿 | clipboard | cloud-mcp-panel.mjs |
| `cloud.callback.sourcePaste` | 貼上 | pasted | cloud-mcp-panel.mjs |
| `cloud.callback.accepted` | 回呼網址已送到本機伺服器記憶體（{source}），頁面不保留內容；{at} 前有效，只能使用一次。 | Callback URL sent to local server memory ({source}); the page keeps nothing. Valid until {at}, single use. | cloud-mcp-panel.mjs |
| `cloud.callback.rejected` | 回呼網址未接受：{reason} | Callback URL not accepted: {reason} | cloud-mcp-panel.mjs |
| `cloud.switch.runningOn` | 正在執行：打開軟體開關（真實 AWS 呼叫）… | Running: turning the software switch ON (real AWS call)… | cloud-mcp-panel.mjs |
| `cloud.switch.runningOff` | 正在執行：關閉軟體開關（真實 AWS 呼叫）… | Running: turning the software switch OFF (real AWS call)… | cloud-mcp-panel.mjs |
| `cloud.step.workerSummary` | Mac worker：{status}，executed={executed}；mode={mode} | Mac worker: {status}, executed={executed}; mode={mode} | cloud-mcp-panel.mjs |
| `cloud.result.done` | 完成 | Done | cloud-mcp-panel.mjs |
| `cloud.result.notDone` | 未完成 | Not completed | cloud-mcp-panel.mjs |
| `cloud.result.line` | {verdict}：result.status={status}，executed={executed}，enabled={enabled}，revision={revision}，commandId={commandId}，mode={mode}（簡化保證）。 | {verdict}: result.status={status}, executed={executed}, enabled={enabled}, revision={revision}, commandId={commandId}, mode={mode} (reduced assurance). | cloud-mcp-panel.mjs |
| `cloud.result.streamFailed` | 未完成：{code}。登入碼已用掉，請重新按「Cognito 登入」。 | Not completed: {code}. The login code has been used; press "Cognito login" again. | cloud-mcp-panel.mjs |
| `cloud.result.notRun` | 未執行：{reason} | Not run: {reason} | cloud-mcp-panel.mjs |
| `cloud.step.gate` | 本機門禁通過（owner 登入；操作碼已於雲端登入時核對）；Mac 金鑰已於伺服器啟動時在 Terminal 以隱藏輸入解鎖，密語不經瀏覽器 | Local gate passed (owner login; operator code checked at cloud login); Mac key was unlocked by hidden Terminal input at server start; the passphrase never passes through the browser | src/cloud_mcp_panel.mjs |
| `cloud.step.gateTestSource` | 本機門禁通過（owner 登入；操作碼已於雲端登入時核對）；Mac 金鑰已於伺服器啟動時在 Terminal 以隱藏輸入解鎖，密語不經瀏覽器（測試來源） | Local gate passed (owner login; operator code checked at cloud login); Mac key was unlocked by hidden Terminal input at server start; the passphrase never passes through the browser (TEST source) | src/cloud_mcp_panel.mjs |
| `cloud.step.start` | 開始 demo-switch：mode=software-direct，enabled={enabled} | demo-switch started: mode=software-direct, enabled={enabled} | src/cloud_mcp_panel.mjs |
| `cloud.step.cognitoReused` | 沿用這次登入的 Cognito 工作階段（權杖只在伺服器記憶體，不顯示） | Reusing this login's Cognito session (token kept only in server memory, not shown) | src/cloud_mcp_panel.mjs |
| `cloud.step.cognito` | Cognito 授權碼交換完成（權杖只在伺服器記憶體，不顯示） | Cognito authorization code exchanged (token kept only in server memory, not shown) | src/cloud_mcp_panel.mjs |
| `cloud.step.set` | 雲端 MCP tools/call software_test_switch.set → {status}，commandId={commandId} | Cloud MCP tools/call software_test_switch.set → {status}, commandId={commandId} | src/cloud_mcp_panel.mjs |
| `cloud.step.poll` | Mac worker 第 {n} 次 fetch/verify/execute/receipt：{status} | Mac worker fetch/verify/execute/receipt #{n}: {status} | src/cloud_mcp_panel.mjs |
| `cloud.step.pollWithCommand` | Mac worker 第 {n} 次 fetch/verify/execute/receipt：{status}，commandId={commandId} | Mac worker fetch/verify/execute/receipt #{n}: {status}, commandId={commandId} | src/cloud_mcp_panel.mjs |
| `cloud.step.result` | 雲端 MCP tools/call software_test_switch.result → {status}，executed={executed} | Cloud MCP tools/call software_test_switch.result → {status}, executed={executed} | src/cloud_mcp_panel.mjs |
| `cloud.device.label` | 模擬家電動作（經 AWS 雲端鏈） | Simulated home device action (through the AWS cloud chain) | index.html |
| `cloud.device.hint` | 裝置須先配對。開門鎖、解除攝影機與數值設定不開放從雲端控制。 | Pair the device first. Door unlock, camera disarm and value settings are not available from the cloud. | index.html |
| `cloud.device.run` | 經雲端送到家電 | Send to device via cloud | index.html |
| `cloud.device.option` | {device} — {action} | {device} — {action} | cloud-mcp-panel.mjs |
| `cloud.device.running` | 正在執行：{device} — {action}（真實 AWS 呼叫）… | Running: {device} — {action} (real AWS call)… | cloud-mcp-panel.mjs |
| `cloud.step.deviceStart` | 開始 demo-device：mode=software-direct，device={device}，action={action} | demo-device started: mode=software-direct, device={device}, action={action} | src/cloud_mcp_panel.mjs |
| `cloud.step.deviceSet` | 雲端 MCP tools/call home_device.command → {status}，commandId={commandId} | Cloud MCP tools/call home_device.command → {status}, commandId={commandId} | src/cloud_mcp_panel.mjs |
| `cloud.step.deviceResult` | 雲端 MCP tools/call home_device.result → {status}，executed={executed} | Cloud MCP tools/call home_device.result → {status}, executed={executed} | src/cloud_mcp_panel.mjs |
| `cloud.result.deviceLine` | {verdict}：result.status={status}，executed={executed}，device={device}，action={action}，deviceStatus={deviceStatus}，commandId={commandId}，mode={mode}（簡化保證）。 | {verdict}: result.status={status}, executed={executed}, device={device}, action={action}, deviceStatus={deviceStatus}, commandId={commandId}, mode={mode} (reduced assurance). | cloud-mcp-panel.mjs |
| `cloud.result.deviceHint` |  若 executed=false：請先配對該裝置，並保持模擬閘道在線。 |  If executed=false: pair the device first and keep the simulated gateway online. | cloud-mcp-panel.mjs |
| `cloud.err.HOME_DEVICE_ACTION_NOT_ALLOWED` | 此裝置動作不開放從雲端控制。 | This device action is not allowed from the cloud. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.err.HOME_DEVICE_UNAVAILABLE` | 此伺服器未提供家電控制。 | Home device control is not available on this server. | cloud-mcp-panel.mjs (dynamic `cloud.err.*`) |
| `cloud.listen.run` | 等待 AI 代理指令（30 秒） | Wait for an AI agent command (30 s) | index.html |
| `cloud.listen.hint` | 先按這裡，再讓 AI 代理透過 MCP bridge 呼叫 home_device.command。配對與白名單規則相同。 | Start this, then let your agent call home_device.command through the MCP bridge. The same pairing and allowlist gates apply. | index.html |
| `cloud.listen.running` | 最多等待 30 秒，接收一個 AI 代理送來的指令（真實 AWS 呼叫）… | Waiting up to 30 s for one command from an AI agent (real AWS call)… | cloud-mcp-panel.mjs |
| `cloud.step.listenStart` | 開始 listen-device：mode=software-direct，最多取件 {polls} 次 | listen-device started: mode=software-direct, up to {polls} fetches | src/cloud_mcp_panel.mjs |
| `cloud.step.listenApplied` | AI 代理指令已在本機套用：device={device}，action={action} → {status} | Agent command applied locally: device={device}, action={action} → {status} | src/cloud_mcp_panel.mjs |
| `cloud.result.listenEmpty` | 30 秒內沒有收到 AI 代理指令，沒有套用任何動作。 | No agent command arrived in the 30 s window; nothing was applied. | cloud-mcp-panel.mjs |
| `cloud.step.redacted` | 步驟（已遮蔽） | Step (redacted) | cloud-mcp-panel.mjs, src/cloud_mcp_panel.mjs |
| `edge.heading` | ESP32-C3 邊緣閘道 · SIMULATED | ESP32-C3 edge gateway · SIMULATED | index.html |
| `edge.intro` | 模擬家中 ESP32-C3 連上 Wi‑Fi、送出心跳與轉送 MCP 指令。斷線時短效命令進入 fallback 佇列；排隊或閘道回執都不能證明實體電器已動作。本頁不會連接 Wi‑Fi 或發射紅外線。 | Simulates a home ESP32-C3 joining Wi‑Fi, sending heartbeats and relaying MCP commands. While disconnected, short-lived commands go to a fallback queue; neither queueing nor a gateway receipt proves a physical appliance acted. This page never connects to Wi‑Fi or emits infrared. | index.html |
| `edge.online.unknown` | 尚未取得狀態 | Status not available yet | index.html, index.html (script) |
| `edge.online.fresh` | 模擬在線／心跳正常 | Simulated online / heartbeat OK | index.html (script) |
| `edge.online.waiting` | 模擬連線待心跳 | Simulated connected, awaiting heartbeat | index.html (script) |
| `edge.online.offline` | 模擬離線 | Simulated offline | index.html (script) |
| `edge.heartbeat.initial` | 最後心跳：— | Last heartbeat: — | index.html |
| `edge.heartbeat` | 最後心跳：{at} | Last heartbeat: {at} | index.html (script) |
| `edge.pending.initial` | 待送命令：— | Commands pending: — | index.html |
| `edge.pending` | 待送命令：{count} | Commands pending: {count} | index.html (script) |
| `edge.disconnect` | 模擬斷線 | Simulate disconnect | index.html |
| `edge.reconnect` | 模擬重連 | Simulate reconnect | index.html |
| `edge.heartbeatButton` | 送出模擬心跳 | Send simulated heartbeat | index.html |
| `edge.scene` | MCP 一對多：回家場景 | MCP one-to-many: Arriving-home scene | index.html |
| `edge.sceneNote` | 回家場景逐一要求客廳燈、冷氣、除濕機開啟；每個裝置仍需個別模擬配對與授權，結果會分開列出。門鎖不在此場景內。 | The arriving-home scene asks the living room light, air conditioner and dehumidifier to turn on one by one; each device still needs its own simulated pairing and authorization, and results are listed separately. The door lock is not part of this scene. | index.html |
| `edge.latestHeading` | 各設備最近一筆命令 | Latest command per device | index.html |
| `edge.batchHeading` | 本次一對多結果 | Results of this one-to-many run | index.html |
| `edge.status.simulated_applied` | 模擬閘道已套用；未驗證實體裝置 | Applied by simulated gateway; physical device not verified | index.html (script) |
| `edge.status.queued` | 斷線，已進 fallback 佇列 | Disconnected, queued in fallback | index.html (script) |
| `edge.status.expired` | 命令已過期，未執行 | Command expired, not executed | index.html (script) |
| `edge.status.denied` | 授權拒絕，未執行 | Authorization denied, not executed | index.html (script) |
| `edge.status.dropped` | 命令未送達 | Command not delivered | index.html (script) |
| `edge.status.accepted` | 後端已受理，尚無執行回執 | Accepted by backend, no execution receipt yet | index.html (script) |
| `edge.status.undetermined` | 未判定：{status} | Undetermined: {status} | index.html (script) |
| `edge.status.none` | 尚無命令回執 | No command receipt yet | index.html (script) |
| `edge.result.simulated` | {status} · SIMULATED | {status} · SIMULATED | index.html (script) |
| `edge.detail.command` | 命令：{id} | Command: {id} | index.html (script) |
| `edge.detail.time` | 時間：{at} | Time: {at} | index.html (script) |
| `edge.detail.expires` | 有效至：{at} | Valid until: {at} | index.html (script) |
| `edge.signal.sent` | 模擬訊號已送 | Simulated signal sent | index.html (script) |
| `edge.signal.none` | 無送出證據 | No evidence of sending | index.html (script) |
| `edge.ack.yes` | 模擬閘道已回執 | Simulated gateway acknowledged | index.html (script) |
| `edge.ack.no` | 無閘道回執 | No gateway receipt | index.html (script) |
| `edge.observed.yes` | 有裝置回讀 | Device read-back present | index.html (script) |
| `edge.observed.no` | 無實體裝置回讀 | No physical device read-back | index.html (script) |
| `edge.receipts.empty` | 尚無模擬設備或命令回執。 | No simulated devices or command receipts yet. | index.html (script) |
| `devices.heading` | 設備 | Devices | index.html |
| `devices.intro` | 配對碼、執行結果及狀態皆由本機模擬器產生。 | Pairing codes, results and states are all produced by the local simulator. | index.html |
| `device.robot_vacuum.name` | 掃地機器人 | Robot vacuum | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.robot_vacuum.label` | 掃地機器人 | Robot vacuum | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.robot_vacuum.note` | 虛擬清掃狀態 | Virtual cleaning state | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.robot_vacuum.action.start` | 開始清掃 | Start cleaning | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.robot_vacuum.action.pause` | 暫停 | Pause | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.robot_vacuum.action.dock` | 返回充電座 | Return to dock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.name` | 冷氣 | Air conditioner | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.label` | 冷氣 | Air conditioner | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.note` | 模擬紅外線冷氣與 Wi-Fi 橋接器 | Simulated infrared AC with Wi-Fi bridge | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.action.on` | 開啟 | Turn on | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.action.off` | 關閉 | Turn off | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.air_conditioner.action.set_temperature` | 設定溫度 | Set temperature | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.front_door.name` | 門鎖 | Door lock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.front_door.label` | 門鎖 | Door lock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.front_door.note` | 模擬 Wi-Fi 橋接與逐次解鎖 | Simulated Wi-Fi bridge, per-action unlock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.front_door.action.lock` | 上鎖 | Lock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.front_door.action.unlock` | 解鎖 | Unlock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.alarm_clock.name` | 電子鬧鐘 | Alarm clock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.alarm_clock.label` | 電子鬧鐘 | Alarm clock | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.alarm_clock.note` | 虛擬鬧鐘時間 | Virtual alarm time | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.alarm_clock.action.set_alarm` | 設定鬧鐘 | Set alarm | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.alarm_clock.action.clear_alarm` | 清除鬧鐘 | Clear alarm | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.living_light.name` | 燈光 | Light | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.living_light.label` | 客廳燈 | Living room light | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.living_light.note` | 虛擬燈光狀態 | Virtual light state | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.living_light.action.on` | 開燈 | Light on | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.living_light.action.off` | 關燈 | Light off | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.camera.name` | 監控攝影機 | Security camera | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.camera.label` | 監視器（狀態模擬） | Camera (state simulated) | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.camera.note` | 只模擬啟用狀態；無影像 | Only the armed state is simulated; no video | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.camera.action.arm` | 啟用 | Arm | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.camera.action.disarm` | 停用 | Disarm | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.name` | 除濕機 | Dehumidifier | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.label` | 除濕機 | Dehumidifier | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.note` | 虛擬目標濕度 | Virtual target humidity | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.action.on` | 開啟 | Turn on | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.action.off` | 關閉 | Turn off | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.dehumidifier.action.set_target_humidity` | 設定濕度 | Set humidity | cloud-mcp-panel.mjs (dynamic `device.*`), guardian.mjs (dynamic `device.*`), index.html (script) (dynamic `device.*`) |
| `device.unknown` | 未知設備 | Unknown device | index.html (script) |
| `device.unknownAction` | 未知動作 | Unknown action | index.html (script) |
| `device.genericNote` | 虛擬設備 | Virtual device | index.html (script) |
| `device.noState` | 尚無狀態 | No state yet | index.html (script) |
| `device.paired` | 已模擬配對 | Simulated pairing done | index.html (script) |
| `device.unpaired` | 未配對 | Not paired | index.html (script) |
| `device.stateAria` | {name}目前狀態 | {name} current state | index.html (script) |
| `device.pair` | 模擬配對 | Simulate pairing | index.html (script) |
| `device.footnote` | ID: {id} · SIMULATED | ID: {id} · SIMULATED | index.html (script) |
| `device.footnoteAc` | ID: {id} · SIMULATED · 此處僅顯示請求後的虛擬狀態，無紅外線回讀 | ID: {id} · SIMULATED · Shows only the virtual state after the request; no infrared read-back | index.html (script) |
| `param.temperature` | 溫度（16–30°C） | Temperature (16–30°C) | index.html (script) |
| `param.time` | 鬧鐘時間 | Alarm time | index.html (script) |
| `param.humidity` | 目標濕度（30–80%） | Target humidity (30–80%) | index.html (script) |
| `param.dialogDescription` | 輸入這次模擬指令的參數。 | Enter the parameter for this simulated command. | index.html (script) |
| `param.range` | {label}需介於 {min} 與 {max} 之間。 | {label} must be between {min} and {max}. | index.html (script) |
| `param.timeInvalid` | 請輸入有效的 HH:MM 時間。 | Enter a valid HH:MM time. | index.html (script) |
| `schedule.heading` | 建立安全排程 | Create a safe schedule | index.html |
| `schedule.intro` | 只開放模擬器允許的低風險動作。門鎖解鎖不可排程。 | Only low-risk actions allowed by the simulator. Door unlock cannot be scheduled. | index.html |
| `schedule.device` | 設備 | Device | index.html |
| `schedule.action` | 動作 | Action | index.html |
| `schedule.param` | 參數 | Parameter | index.html |
| `schedule.at` | 執行時間 | Run at | index.html |
| `schedule.atPlaceholder` | YYYY-MM-DD HH:MM（24 小時制） | YYYY-MM-DD HH:MM (24-hour) | index.html (placeholder) |
| `schedule.atFormat` | 執行時間請輸入 YYYY-MM-DD HH:MM（24 小時制）。 | Enter the run time as YYYY-MM-DD HH:MM (24-hour). | index.html (script) |
| `schedule.submit` | 加入模擬排程 | Add simulated schedule | index.html |
| `schedule.pendingHeading` | 待執行 | Pending | index.html |
| `schedule.chooseDevice` | 選擇已配對設備 | Choose a paired device | index.html (script) |
| `schedule.chooseAction` | 選擇動作 | Choose an action | index.html (script) |
| `schedule.empty` | 尚無待執行排程。 | No pending schedules. | index.html (script) |
| `schedule.cancelAria` | 取消 {device} {action} 排程 | Cancel {device} {action} schedule | index.html (script) |
| `schedule.notAllowed` | 這個動作不允許排程。 | This action cannot be scheduled. | index.html (script) |
| `schedule.paramOutOfRange` | {label}不在允許範圍。 | {label} is out of the allowed range. | index.html (script) |
| `schedule.alarmInvalid` | 鬧鐘時間需為 HH:MM。 | Alarm time must be HH:MM. | index.html (script) |
| `schedule.mustBeFuture` | 排程時間必須在未來。 | The schedule time must be in the future. | index.html (script) |
| `audit.heading` | 活動紀錄：AI 代理與屋主的動作 | Activity: AI agent and owner actions | index.html |
| `audit.intro` | 記錄每次配對、指令（本機、MCP 或雲端）與排程結果，最新的在最上面；所有紀錄均為模擬。 | Every pairing, command (local, MCP or cloud) and schedule result, newest first; all records are simulated. | index.html |
| `audit.empty` | 尚無稽核紀錄。 | No audit records yet. | index.html (script) |
| `audit.recorded` | 已記錄 | recorded | index.html (script) |
| `audit.row` | {outcome} · {origin} · SIMULATED | {outcome} · {origin} · SIMULATED | index.html (script) |
| `audit.originDefault` | UI | UI | index.html (script) |
| `common.cancel` | 取消 | Cancel | index.html (script) |
| `common.confirm` | 確認 | Confirm | index.html (script) |
| `common.continue` | 繼續 | Continue | index.html (script) |
| `dialog.mockMailNote` | 本機模擬訊息；未寄送電子郵件，也不是獨立驗證因素。 | Local simulated message; no email was sent, and it is not an independent verification factor. | index.html (script) |
| `dialog.codeLabel` | 模擬碼 | Simulated code | index.html (script) |
| `pair.description.front_door` | 模擬電子鎖與 Wi-Fi 橋接器配對，再由 Mac mini 管理請求；不會搜尋或加入家中 Wi-Fi。配對碼有效至 {at}。 | Simulates pairing an electronic lock with a Wi-Fi bridge, with requests managed by a Mac mini; does not search for or join home Wi-Fi. Pairing code valid until {at}. | index.html (script) |
| `pair.description.air_conditioner` | 模擬 Mac mini 向 Wi-Fi 紅外線橋接器發送冷氣指令；不會搜尋 Wi-Fi、發射紅外線或確認實機狀態。配對碼有效至 {at}。 | Simulates a Mac mini sending AC commands to a Wi-Fi infrared bridge; does not search Wi-Fi, emit infrared or confirm real device state. Pairing code valid until {at}. | index.html (script) |
| `pair.description.generic` | 這是虛擬設備，不會搜尋或加入家中 Wi‑Fi。配對碼有效至 {at}。 | This is a virtual device; it does not search for or join home Wi‑Fi. Pairing code valid until {at}. | index.html (script) |
| `pair.title` | 模擬配對 · {name} | Simulated pairing · {name} | index.html (script) |
| `pair.codeLabel` | 模擬配對碼 | Simulated pairing code | index.html (script) |
| `pair.inputLabel` | 請輸入上方配對碼 | Enter the pairing code above | index.html (script) |
| `pair.confirm` | 完成模擬配對 | Complete simulated pairing | index.html (script) |
| `unlock.title` | 模擬信箱確認 · 門鎖解鎖 | Simulated email confirmation · door unlock | — (not referenced: unused key) |
| `unlock.description` | 已建立只限這次虛擬門鎖解鎖的短效請求，有效至 {at}。先開啟下方模擬收件匣，再輸入訊息中的驗證碼。 | A short-lived request for this virtual door unlock only was created, valid until {at}. Open the simulated inbox below, then enter the code from the message. | — (not referenced: unused key) |
| `unlock.alert` | 這是本機流程展示；沒有寄信、沒有連接實體門鎖。 | This is a local flow demo; no email is sent and no physical lock is connected. | — (not referenced: unused key) |
| `unlock.codeLabel` | 本次短效驗證碼 | Short-lived code for this request | — (not referenced: unused key) |
| `unlock.reveal` | 開啟模擬收件匣 | Open simulated inbox | — (not referenced: unused key) |
| `unlock.inputLabel` | 輸入模擬郵件中的驗證碼 | Enter the code from the simulated email | — (not referenced: unused key) |
| `unlock.confirm` | 透過 MCP 模擬解鎖 | Simulate unlock via MCP | — (not referenced: unused key) |
| `unlock.noResult` | MCP 沒有回傳虛擬門鎖解鎖結果。 | MCP did not return a virtual door unlock result. | — (not referenced: unused key) |
| `notice.mcpUnverified` | MCP 後端沒有回傳可驗證的模擬結果；不宣告動作成功。 | The MCP backend returned no verifiable simulated result; the action is not reported as successful. | index.html (script) |
| `notice.loggedOut` | 已登出。本頁沒有儲存登入權杖。 | Logged out. This page did not store the login token. | index.html (script) |
| `notice.scheduleCancelled` | 模擬排程已取消。 | Simulated schedule cancelled. | index.html (script) |
| `notice.paired` | {name}已完成模擬配對。 | {name}: simulated pairing complete. | index.html (script) |
| `notice.unlocked` | 門鎖已通過短效確認，MCP 回傳虛擬解鎖結果（模擬）。 | Door lock passed the short-lived confirmation; MCP returned a virtual unlock result (simulated). | — (not referenced: unused key) |
| `notice.notSimulated` | 後端未確認這是模擬結果；不宣告裝置動作完成。 | The backend did not confirm this is a simulated result; the device action is not reported as done. | index.html (script) |
| `notice.actionApplied` | {name}：{action}已由模擬閘道套用；沒有實體設備回讀。 | {name}: {action} applied by the simulated gateway; no physical device read-back. | index.html (script) |
| `notice.actionQueued` | {name}：{action}已進 fallback 佇列，尚未執行。 | {name}: {action} queued in fallback, not executed yet. | index.html (script) |
| `notice.actionOther` | {name}：{status}。 | {name}: {status}. | index.html (script) |
| `notice.operationFailed` | 操作失敗。 | Operation failed. | index.html (script) |
| `notice.loggedIn` | 已登入本機模擬控制台。所有裝置及操作均為 SIMULATED。 | Logged in to the local simulated console. All devices and operations are SIMULATED. | index.html (script) |
| `notice.loginFirst` | 請先登入模擬控制台。 | Log in to the simulated console first. | index.html (script) |
| `notice.clipboardUnsupported` | 瀏覽器不支援剪貼簿，請使用 localhost 或安全環境開啟。  | This browser does not support the clipboard; open the page on localhost or a secure context. | index.html (script) |
| `notice.tokenCopied` | 本次 MCP 權杖已複製。它只代表本機模擬器登入階段，登出時會撤銷。 | This session’s MCP token was copied. It only represents the local simulator login session and is revoked on logout. | index.html (script) |
| `notice.refreshed` | 模擬狀態已更新。 | Simulated state refreshed. | index.html (script) |
| `notice.edgeDisconnected` | ESP32-C3 已模擬斷線；後續可排隊的命令不會標為已執行。 | ESP32-C3 simulated disconnect; later queueable commands will not be marked as executed. | index.html (script) |
| `notice.edgeReconnected` | ESP32-C3 已模擬重連；請查看每筆命令的獨立回執。 | ESP32-C3 simulated reconnect; check each command’s own receipt. | index.html (script) |
| `notice.heartbeatSent` | 已送出模擬心跳；這只表示閘道連線狀態。 | Simulated heartbeat sent; it only reflects the gateway connection state. | index.html (script) |
| `notice.sceneUnverified` | MCP 沒有回傳逐設備模擬結果；無法判定場景是否完成。 | MCP returned no per-device simulated results; cannot tell whether the scene completed. | index.html (script) |
| `notice.sceneResult` | 一對多 MCP 已回傳 {total} 筆模擬結果：模擬閘道套用 {applied}、fallback 排隊 {queued}、其他 {other}。請逐筆查看。 | One-to-many MCP returned {total} simulated result(s): applied by simulated gateway {applied}, queued in fallback {queued}, other {other}. Check each one. | index.html (script) |
| `notice.scheduleAdded` | 安全動作已加入模擬排程。 | Safe action added to the simulated schedule. | index.html (script) |
