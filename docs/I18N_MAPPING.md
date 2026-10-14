# I18N_MAPPING — UI text mapping table (中文 ↔ English)

English is the default UI language; Chinese is available with `?lang=zh`.

* Source of truth: `public/i18n-map.mjs` (`I18N_MAP`, frozen `{ key: { en, zh } }`, plus `t(key, params)`). This file is generated from the same table.
* Default language: **English**. Chinese: open `http://127.0.0.1:8765/?lang=zh` (or click the `中文` / `English` link in the header; it reloads the page, so pick the language **before** logging in).
* Markup uses `data-i18n="key"` / `data-i18n-aria-label="key"`; scripts call `t('key', { param })`. `{name}` = runtime parameter.
* Server step lines are sent as stable codes `{ key: 'cloud.step.*', params }` by `src/cloud_mcp_panel.mjs` and rendered by the client through this table.
* Not translated (by design): protocol / code values shown verbatim (`result.status=SUCCEEDED`, `executed=true`, `commandId=cmd_…`, error codes such as `MAC_KEY_NOT_READY`, device ids), audit `outcome`/`action` codes from the simulator, device icons (◇ ❄ ▣ ◷ ☼ ◎ ♧) and the brand mark `M`.

Total keys: **411**

| key | 中文 | English | where used |
| --- | --- | --- | --- |
| `locale` | zh-TW | en-US | index.html (script), cloud-mcp-panel.mjs (date/time format) |
| `html.lang` | zh-Hant | en | i18n-map.mjs |
| `lang.toggle` | English | 中文 | index.html header (language switch) |
| `lang.toggleAria` | 切換為英文介面 | Switch the interface to Chinese | index.html header |
| `page.title` | Home MCP · 虛擬設備控制台 | Home MCP · Virtual Device Console | index.html <title> |
| `brand.name` | Home MCP | Home MCP | index.html header |
| `header.subtitle` | 七設備授權控制台 | Seven-device authorization console | index.html header |
| `header.badge` | SIMULATED | SIMULATED | index.html header |
| `header.note` | 七設備純本機模擬 · Ring 僅手動唯讀探索及 History 能力探測 · 未連接 Wi‑Fi、硬體或雲端 | Seven devices are SIMULATED (local only) · Ring: manual read-only discovery and History capability probe only · No Wi‑Fi, hardware or cloud connection | index.html header |
| `header.logout` | 登出 | Log out | index.html header |
| `login.heading` | 進入私人控制介面 | Enter the private control console | index.html |
| `login.intro` | 輸入本機示範通行碼。此頁只模擬裝置、配對與指令，不會控制家中設備。 | Enter the local demo passcode. This page only simulates devices, pairing and commands; it does not control any home device. | index.html |
| `login.passcode.label` | 示範通行碼 | Demo passcode | index.html |
| `login.passcode.hint` | 通行碼由本機伺服器提供；請勿輸入真實帳號密碼。 | The passcode comes from the local server; do not enter a real account password. | index.html |
| `login.submit` | 登入模擬控制台 | Log in to the simulated console | index.html |
| `hero.heading` | 家庭設備，單一授權入口 | Home devices, one authorization entry point | index.html |
| `hero.intro` | 七個虛擬設備共用配對、逐次授權、排程與稽核流程。 | Seven virtual devices share pairing, per-action authorization, scheduling and audit. | index.html |
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
| `wifi.phase.disabled` | 家庭 Wi-Fi 授權尚未啟用。正式家庭身分連接完成前，不會建立替代身分或本地信任。 | Home Wi-Fi authorization is not enabled. Until the formal household identity is connected, no substitute identity or local trust is created. | wifi-permission-controller.mjs |
| `wifi.phase.idle` | 尚未讀取家庭 Wi-Fi 授權狀態。家庭 Wi-Fi 只用來選擇本地加密傳輸；進入 MCP 時仍會自動簽發短效憑證。 | Home Wi-Fi authorization status not read yet. Home Wi-Fi only selects local encrypted transport; entering MCP still issues a short-lived credential automatically. | wifi-permission-controller.mjs |
| `wifi.phase.pending` | 正在處理家庭 Wi-Fi 授權，請稍候。 | Processing home Wi-Fi authorization, please wait. | wifi-permission-controller.mjs |
| `wifi.phase.active` | 已授權此家庭 Wi-Fi。它只會選擇本地加密傳輸；進入 MCP 時仍會自動簽發短效憑證。 | This home Wi-Fi is authorized. It only selects local encrypted transport; entering MCP still issues a short-lived credential automatically. | wifi-permission-controller.mjs |
| `wifi.phase.revoked` | 家庭 Wi-Fi 授權已撤銷。下次進入 MCP 時仍會依入口規則自動簽發短效憑證。 | Home Wi-Fi authorization revoked. The next MCP entry still issues a short-lived credential automatically under the entry rules. | wifi-permission-controller.mjs |
| `wifi.phase.denied` | 家庭 Wi-Fi 授權未通過。請確認授權意願後再試一次。 | Home Wi-Fi authorization was not granted. Confirm your consent and try again. | wifi-permission-controller.mjs |
| `wifi.phase.adapter-error` | 無法讀取或更新家庭 Wi-Fi 授權。請稍後再試。 | Could not read or update home Wi-Fi authorization. Please try again later. | wifi-permission-controller.mjs |
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
| `ring.diag.op.NONE` | 尚無 | none | index.html (script) |
| `ring.diag.op.IMPORT` | 匯入權杖 | import token | index.html (script) |
| `ring.diag.op.DISCOVERY` | 查詢裝置 | query devices | index.html (script) |
| `ring.diag.op.HISTORY` | 查詢 Motion 紀錄 | query Motion history | index.html (script) |
| `ring.diag.op.CAPTURE` | 擷取候選回執 | capture candidate receipt | index.html (script) |
| `ring.diag.gate.NOT_CHECKED` | 尚未驗證 | not verified yet | index.html (script) |
| `ring.diag.gate.PENDING` | 等待驗證 | awaiting verification | index.html (script) |
| `ring.diag.gate.PASSED` | 本機操作碼已通過 | local operator code passed | index.html (script) |
| `ring.diag.gate.DENIED` | 本機操作碼未通過 | local operator code denied | index.html (script) |
| `ring.diag.gate.UNAVAILABLE` | 本機操作碼尚未設定 | local operator code not configured | index.html (script) |
| `ring.diag.gate.LIMITED` | 需稍後再試 | retry later | index.html (script) |
| `ring.diag.gate.UNKNOWN` | 尚無驗證結論 | no verification verdict | index.html (script) |
| `ring.diag.phase.IDLE` | 尚未送出 | not sent yet | index.html (script) |
| `ring.diag.phase.NOT_SENT` | 未送出 | not sent | index.html (script) |
| `ring.diag.phase.SENDING` | 等待回應 | awaiting response | index.html (script) |
| `ring.diag.phase.COMPLETE` | 已收到回應 | response received | index.html (script) |
| `ring.diag.outcome.LOCAL_IMPORT_OK` | 匯入完成，尚未查證 Ring 權杖 | import done, Ring token not verified yet | index.html (script) |
| `ring.diag.outcome.DISCOVERY_OK` | 裝置查詢完成，未執行裝置動作 | device query done, no device action executed | index.html (script) |
| `ring.diag.outcome.HISTORY_OK` | 紀錄查詢完成，未執行裝置動作 | history query done, no device action executed | index.html (script) |
| `ring.diag.outcome.CAPTURE_PENDING` | 候選回執已保存，待影片及人工驗收 | candidate receipt saved, awaiting video and manual acceptance | index.html (script) |
| `ring.diag.outcome.DISCOVERY_HTTP_401` | Ring 未接受這次授權（401） | Ring did not accept this authorization (401) | index.html (script) |
| `ring.diag.outcome.DISCOVERY_HTTP_403` | Ring 拒絕這次存取（403） | Ring refused this access (403) | index.html (script) |
| `ring.diag.outcome.DISCOVERY_TIMEOUT` | Ring 查詢逾時 | Ring query timed out | index.html (script) |
| `ring.diag.outcome.DISCOVERY_NETWORK_ERROR` | 無法連線至 Ring | Cannot connect to Ring | index.html (script) |
| `ring.diag.outcome.DISCOVERY_NOT_SUCCESSFUL` | Ring 回應格式不符或查詢未完成 | Ring response malformed or query not completed | index.html (script) |
| `ring.diag.outcome.INPUT_EMPTY` | 請先輸入本機獨立操作碼 | Enter the local independent operator code first | index.html (script) |
| `ring.diag.outcome.NOT_STARTED` | 尚無結果 | no result yet | index.html (script) |
| `ring.diag.outcome.PENDING` | 處理中 | in progress | index.html (script) |
| `ring.diag.outcome.fallback` | 未完成 | not completed | index.html (script) |
| `ring.diag.none` | 尚無 | none | index.html (script) |
| `ring.diag.whitespace` | （含空白） |  (contains whitespace) | index.html (script) |
| `ring.diag.sent` | {length} 字，時間：{at} | {length} chars at {at} | index.html (script) |
| `ring.diag.notSent` | 尚未送出請求 | no request sent yet | index.html (script) |
| `ring.diag.text` | 目前輸入 {length} 字{whitespace}；最後輸入：{inputAt}。上一筆操作：{operation}；上一筆送出：{sent}；上一筆清空：{clearedAt}；上一筆進度：{phase}。上一筆本機門禁：{gate}；上一筆步驟：{outcome}（{code}）。目前輸入字數不代表驗證通過；不保留操作碼內容。 | Current input: {length} chars{whitespace}; last input: {inputAt}. Last operation: {operation}; last submit: {sent}; last cleared: {clearedAt}; last progress: {phase}. Last local gate: {gate}; last step: {outcome} ({code}). The current character count does not mean verification passed; the operator code is never kept. | index.html (script) |
| `ring.err.operatorUnavailable` | 本機獨立操作碼尚未設定或設定無效。 | The local independent operator code is not configured or invalid. | index.html (script) |
| `ring.err.operatorDenied` | 本機獨立操作碼未通過驗證。 | The local independent operator code was not accepted. | index.html (script) |
| `ring.err.operatorRateLimit` | 操作碼失敗次數過多，請稍後再試。 | Too many failed operator code attempts; try again later. | index.html (script) |
| `ring.err.clipboardUnavailable` | 本機剪貼簿目前無法讀取。 | The local clipboard cannot be read right now. | index.html (script), cloud-mcp-panel.mjs |
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
| `cloud.intro` | 這一區會真的呼叫 AWS 雲端 MCP：Cognito 登入 → software_test_switch.set → 本機 Mac worker 取件、驗簽、執行軟體開關、回執 → software_test_switch.result。每個動作都要先輸入本機獨立操作碼。Mac 金鑰密語只在啟動伺服器時於 Terminal 隱藏輸入一次，不經過瀏覽器、也不放進環境變數。登入網址不會自動開啟；回呼網址送出後只存在本機伺服器記憶體，且只能使用一次。軟體開關是記憶體內測試開關，不是實體裝置。 | This section makes real calls to the AWS cloud MCP: Cognito login → software_test_switch.set → the local Mac worker fetches, verifies the signature, executes the software switch and sends a receipt → software_test_switch.result. Every action needs the local independent operator code first. The Mac key passphrase is typed once, hidden, in the Terminal when the server starts; it never passes through the browser or an environment variable. The login URL is never opened automatically; a submitted callback URL lives only in local server memory and can be used once. The software switch is an in-memory test switch, not a physical device. | index.html |
| `cloud.operator.label` | 本機獨立操作碼（每個雲端動作一次） | Local independent operator code (once per cloud action) | index.html |
| `cloud.operator.hint` | 與 Ring 匯入共用同一組操作碼及失敗次數限制；送出後立即清空。 | Shares the operator code and failure limit with Ring import; cleared immediately after sending. | index.html |
| `cloud.login` | Cognito 登入 | Cognito login | index.html |
| `common.refreshStatus` | 重新整理狀態 | Refresh status | index.html |
| `cloud.status.initial` | 尚未讀取雲端 MCP 面板狀態。 | Cloud MCP panel status not read yet. | index.html |
| `cloud.login.initial` | 尚未產生 Cognito 登入網址。 | No Cognito login URL generated yet. | index.html |
| `cloud.callback.label` | 登入完成後的回呼網址（…/auth/callback?code=…&state=…） | Callback URL after login (…/auth/callback?code=…&state=…) | index.html |
| `cloud.callback.hint` | 以遮蔽方式輸入；送出後立即清空，頁面不保留。 | Masked input; cleared immediately after sending and never kept by the page. | index.html |
| `cloud.callback.submit` | 送出回呼網址 | Submit callback URL | index.html |
| `cloud.callback.clipboard` | 從本機剪貼簿讀取回呼網址 | Read callback URL from local clipboard | index.html |
| `cloud.callback.initial` | 尚未送出回呼網址。 | Callback URL not submitted yet. | index.html, cloud-mcp-panel.mjs |
| `cloud.switch.on` | 打開軟體開關 | Turn software switch ON | index.html |
| `cloud.switch.off` | 關閉軟體開關 | Turn software switch OFF | index.html |
| `cloud.result.initial` | 尚未執行雲端軟體開關。 | Cloud software switch not run yet. | index.html |
| `cloud.key.ready` | Mac 金鑰：已就緒（伺服器啟動時在 Terminal 隱藏輸入密語解鎖；密語不經瀏覽器，也不放環境變數） | Mac key: ready (unlocked by a hidden passphrase typed in the Terminal at server start; the passphrase never passes through the browser or an environment variable) | cloud-mcp-panel.mjs |
| `cloud.key.passphrase_missing` | Mac 金鑰：未就緒（伺服器啟動時未在 Terminal 輸入密語，請用啟動腳本重新啟動） | Mac key: not ready (no passphrase typed in the Terminal at server start; restart with the start script) | cloud-mcp-panel.mjs |
| `cloud.key.key_unlock_failed` | Mac 金鑰：未就緒（密語無法解鎖金鑰） | Mac key: not ready (the passphrase cannot unlock the key) | cloud-mcp-panel.mjs |
| `cloud.key.key_identity_mismatch` | Mac 金鑰：未就緒（金鑰與身分紀錄不一致） | Mac key: not ready (key does not match the identity record) | cloud-mcp-panel.mjs |
| `cloud.key.identity_missing` | Mac 金鑰：未就緒（狀態目錄沒有已登記的 Mac 身分） | Mac key: not ready (no enrolled Mac identity in the state directory) | cloud-mcp-panel.mjs |
| `cloud.key.state_dir_missing` | Mac 金鑰：未就緒（找不到 Mac 狀態目錄） | Mac key: not ready (Mac state directory not found) | cloud-mcp-panel.mjs |
| `cloud.key.state_dir_invalid` | Mac 金鑰：未就緒（Mac 狀態目錄權限或內容不符） | Mac key: not ready (Mac state directory permissions or contents do not match) | cloud-mcp-panel.mjs |
| `cloud.key.other` | Mac 金鑰：未就緒（{key}） | Mac key: not ready ({key}) | cloud-mcp-panel.mjs |
| `cloud.key.testSource` | 【測試來源：環境變數】 |  [TEST source: environment variable] | cloud-mcp-panel.mjs |
| `cloud.status.mode` | Mac 模式：software-direct（簡化保證） | Mac mode: software-direct (reduced assurance) | cloud-mcp-panel.mjs |
| `cloud.status.loginPending` | Cognito 登入：等待回呼（{at} 前有效） | Cognito login: waiting for callback (valid until {at}) | cloud-mcp-panel.mjs |
| `cloud.status.loginIdle` | Cognito 登入：未進行或已使用 | Cognito login: not started or already used | cloud-mcp-panel.mjs |
| `cloud.status.callbackStaged` | 回呼網址：已送到本機伺服器（待使用一次） | Callback URL: sent to the local server (pending single use) | cloud-mcp-panel.mjs |
| `cloud.status.callbackNone` | 回呼網址：未送出 | Callback URL: not submitted | cloud-mcp-panel.mjs |
| `cloud.status.lastRun` | 上一次執行：{at} {result} | Last run: {at} {result} | cloud-mcp-panel.mjs |
| `cloud.status.lastRunOk` | 成功 | succeeded | cloud-mcp-panel.mjs |
| `cloud.status.lastRunFail` | 未成功 | not successful | cloud-mcp-panel.mjs |
| `cloud.status.separator` | ； | ;  | cloud-mcp-panel.mjs |
| `cloud.status.end` | 。 | . | cloud-mcp-panel.mjs |
| `cloud.status.error` | 雲端 MCP 面板：{reason} | Cloud MCP panel: {reason} | cloud-mcp-panel.mjs |
| `cloud.err.AUTH_REQUIRED` | 請先登入本機控制台。 | Log in to the local console first. | cloud-mcp-panel.mjs |
| `cloud.err.SESSION_EXPIRED` | 本機登入已過期，請重新登入。 | Local login expired; log in again. | cloud-mcp-panel.mjs |
| `cloud.err.CLOUD_PANEL_DISABLED` | 伺服器未啟用雲端 MCP 面板（需以啟動腳本、HOME_MCP_CLOUD_PANEL=1 啟動）。 | The server has the Cloud MCP panel disabled (start it with the start script, HOME_MCP_CLOUD_PANEL=1). | cloud-mcp-panel.mjs |
| `cloud.err.RING_OPERATOR_UNAVAILABLE` | 本機獨立操作碼尚未設定或設定無效。 | The local independent operator code is not configured or invalid. | cloud-mcp-panel.mjs |
| `cloud.err.RING_OPERATOR_DENIED` | 本機獨立操作碼未通過驗證。 | The local independent operator code was not accepted. | cloud-mcp-panel.mjs |
| `cloud.err.RING_OPERATOR_RATE_LIMIT` | 操作碼失敗次數過多，請一分鐘後再試。 | Too many failed operator code attempts; try again in one minute. | cloud-mcp-panel.mjs |
| `cloud.err.CLOUD_INTENT_REQUIRED` | 請求來源不是本頁，已拒絕。 | The request did not come from this page; refused. | cloud-mcp-panel.mjs |
| `cloud.err.CLOUD_MCP_BUSY` | 已有一筆雲端動作正在進行。 | A cloud action is already in progress. | cloud-mcp-panel.mjs |
| `cloud.err.MAC_KEY_NOT_READY` | Mac 金鑰未就緒，無法執行。 | Mac key not ready; cannot run. | cloud-mcp-panel.mjs |
| `cloud.err.CALLBACK_URL_INVALID` | 回呼網址格式不符（只接受本部署的 /auth/callback?code=…&state=…）。 | Callback URL has the wrong shape (only this deployment’s /auth/callback?code=…&state=… is accepted). | cloud-mcp-panel.mjs |
| `cloud.err.CALLBACK_STATE_MISMATCH` | 回呼網址不是這一次登入產生的，請重新按「Cognito 登入」。 | This callback URL is not from the current login; press "Cognito login" again. | cloud-mcp-panel.mjs |
| `cloud.err.LOGIN_NOT_PENDING` | 目前沒有等待中的登入，請先按「Cognito 登入」。 | No login is pending; press "Cognito login" first. | cloud-mcp-panel.mjs |
| `cloud.err.LOGIN_EXPIRED` | 登入網址已過期（10 分鐘），請重新登入。 | The login URL expired (10 minutes); log in again. | cloud-mcp-panel.mjs |
| `cloud.err.CALLBACK_NOT_STAGED` | 尚未送出這次登入的回呼網址（每次開關都需要一次新登入）。 | The callback URL for this login has not been submitted (every switch run needs a new login). | cloud-mcp-panel.mjs |
| `cloud.err.CLIPBOARD_UNAVAILABLE` | 本機剪貼簿目前無法讀取。 | The local clipboard cannot be read right now. | cloud-mcp-panel.mjs |
| `cloud.err.CLOUD_AUTHORIZATION_CHANGED` | 本機授權已變更，請重新操作。 | Local authorization changed; please start over. | cloud-mcp-panel.mjs |
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
| `cloud.step.gate` | 本機門禁通過（owner 登入 + 操作碼）；Mac 金鑰已於伺服器啟動時在 Terminal 以隱藏輸入解鎖，密語不經瀏覽器 | Local gate passed (owner login + operator code); Mac key was unlocked by hidden Terminal input at server start; the passphrase never passes through the browser | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.gateTestSource` | 本機門禁通過（owner 登入 + 操作碼）；Mac 金鑰已於伺服器啟動時在 Terminal 以隱藏輸入解鎖，密語不經瀏覽器（測試來源） | Local gate passed (owner login + operator code); Mac key was unlocked by hidden Terminal input at server start; the passphrase never passes through the browser (TEST source) | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.start` | 開始 demo-switch：mode=software-direct，enabled={enabled} | demo-switch started: mode=software-direct, enabled={enabled} | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.cognito` | Cognito 授權碼交換完成（權杖只在伺服器記憶體，不顯示） | Cognito authorization code exchanged (token kept only in server memory, not shown) | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.set` | 雲端 MCP tools/call software_test_switch.set → {status}，commandId={commandId} | Cloud MCP tools/call software_test_switch.set → {status}, commandId={commandId} | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.poll` | Mac worker 第 {n} 次 fetch/verify/execute/receipt：{status} | Mac worker fetch/verify/execute/receipt #{n}: {status} | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.pollWithCommand` | Mac worker 第 {n} 次 fetch/verify/execute/receipt：{status}，commandId={commandId} | Mac worker fetch/verify/execute/receipt #{n}: {status}, commandId={commandId} | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.result` | 雲端 MCP tools/call software_test_switch.result → {status}，executed={executed} | Cloud MCP tools/call software_test_switch.result → {status}, executed={executed} | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
| `cloud.step.redacted` | 步驟（已遮蔽） | Step (redacted) | src/cloud_mcp_panel.mjs → cloud-mcp-panel.mjs |
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
| `device.robot_vacuum.name` | 掃地機器人 | Robot vacuum | index.html (script) |
| `device.robot_vacuum.label` | 掃地機器人 | Robot vacuum | index.html (script) (replaces server label) |
| `device.robot_vacuum.note` | 虛擬清掃狀態 | Virtual cleaning state | index.html (script) |
| `device.robot_vacuum.action.start` | 開始清掃 | Start cleaning | index.html (script) |
| `device.robot_vacuum.action.pause` | 暫停 | Pause | index.html (script) |
| `device.robot_vacuum.action.dock` | 返回充電座 | Return to dock | index.html (script) |
| `device.air_conditioner.name` | 冷氣 | Air conditioner | index.html (script) |
| `device.air_conditioner.label` | 冷氣 | Air conditioner | index.html (script) (replaces server label) |
| `device.air_conditioner.note` | 模擬紅外線冷氣與 Wi-Fi 橋接器 | Simulated infrared AC with Wi-Fi bridge | index.html (script) |
| `device.air_conditioner.action.on` | 開啟 | Turn on | index.html (script) |
| `device.air_conditioner.action.off` | 關閉 | Turn off | index.html (script) |
| `device.air_conditioner.action.set_temperature` | 設定溫度 | Set temperature | index.html (script) |
| `device.front_door.name` | 門鎖 | Door lock | index.html (script) |
| `device.front_door.label` | 門鎖 | Door lock | index.html (script) (replaces server label) |
| `device.front_door.note` | 模擬 Wi-Fi 橋接與逐次解鎖 | Simulated Wi-Fi bridge, per-action unlock | index.html (script) |
| `device.front_door.action.lock` | 上鎖 | Lock | index.html (script) |
| `device.front_door.action.unlock` | 解鎖 | Unlock | index.html (script) |
| `device.alarm_clock.name` | 電子鬧鐘 | Alarm clock | index.html (script) |
| `device.alarm_clock.label` | 電子鬧鐘 | Alarm clock | index.html (script) (replaces server label) |
| `device.alarm_clock.note` | 虛擬鬧鐘時間 | Virtual alarm time | index.html (script) |
| `device.alarm_clock.action.set_alarm` | 設定鬧鐘 | Set alarm | index.html (script) |
| `device.alarm_clock.action.clear_alarm` | 清除鬧鐘 | Clear alarm | index.html (script) |
| `device.living_light.name` | 燈光 | Light | index.html (script) |
| `device.living_light.label` | 客廳燈 | Living room light | index.html (script) (replaces server label) |
| `device.living_light.note` | 虛擬燈光狀態 | Virtual light state | index.html (script) |
| `device.living_light.action.on` | 開燈 | Light on | index.html (script) |
| `device.living_light.action.off` | 關燈 | Light off | index.html (script) |
| `device.camera.name` | 監控攝影機 | Security camera | index.html (script) |
| `device.camera.label` | 監視器（狀態模擬） | Camera (state simulated) | index.html (script) (replaces server label) |
| `device.camera.note` | 只模擬啟用狀態；無影像 | Only the armed state is simulated; no video | index.html (script) |
| `device.camera.action.arm` | 啟用 | Arm | index.html (script) |
| `device.camera.action.disarm` | 停用 | Disarm | index.html (script) |
| `device.dehumidifier.name` | 除濕機 | Dehumidifier | index.html (script) |
| `device.dehumidifier.label` | 除濕機 | Dehumidifier | index.html (script) (replaces server label) |
| `device.dehumidifier.note` | 虛擬目標濕度 | Virtual target humidity | index.html (script) |
| `device.dehumidifier.action.on` | 開啟 | Turn on | index.html (script) |
| `device.dehumidifier.action.off` | 關閉 | Turn off | index.html (script) |
| `device.dehumidifier.action.set_target_humidity` | 設定濕度 | Set humidity | index.html (script) |
| `device.unknown` | 未知設備 | Unknown device | index.html (script) |
| `device.unknownAction` | 未知動作 | Unknown action | index.html (script) |
| `device.genericNote` | 虛擬設備 | Virtual device | index.html (script) |
| `device.noState` | 尚無狀態 | No state yet | index.html (script) |
| `device.paired` | 已模擬配對 | Simulated pairing done | index.html (script) |
| `device.unpaired` | 未配對 | Not paired | index.html (script) |
| `device.stateAria` | {name}目前狀態 | {name} current state | index.html (script) (aria-label) |
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
| `schedule.atPlaceholder` | YYYY-MM-DD HH:MM（24 小時制） | YYYY-MM-DD HH:MM (24-hour) | index.html |
| `schedule.atFormat` | 執行時間請輸入 YYYY-MM-DD HH:MM（24 小時制）。 | Enter the run time as YYYY-MM-DD HH:MM (24-hour). | index.html |
| `schedule.submit` | 加入模擬排程 | Add simulated schedule | index.html |
| `schedule.pendingHeading` | 待執行 | Pending | index.html |
| `schedule.chooseDevice` | 選擇已配對設備 | Choose a paired device | index.html (script) |
| `schedule.chooseAction` | 選擇動作 | Choose an action | index.html (script) |
| `schedule.empty` | 尚無待執行排程。 | No pending schedules. | index.html (script) |
| `schedule.cancelAria` | 取消 {device} {action} 排程 | Cancel {device} {action} schedule | index.html (script) (aria-label) |
| `schedule.notAllowed` | 這個動作不允許排程。 | This action cannot be scheduled. | index.html (script) |
| `schedule.paramOutOfRange` | {label}不在允許範圍。 | {label} is out of the allowed range. | index.html (script) |
| `schedule.alarmInvalid` | 鬧鐘時間需為 HH:MM。 | Alarm time must be HH:MM. | index.html (script) |
| `schedule.mustBeFuture` | 排程時間必須在未來。 | The schedule time must be in the future. | index.html (script) |
| `audit.heading` | 稽核紀錄 | Audit log | index.html |
| `audit.intro` | 記錄配對、操作與排程結果；所有紀錄均為模擬。 | Records pairing, operations and schedule results; all records are simulated. | index.html |
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
| `unlock.title` | 模擬信箱確認 · 門鎖解鎖 | Simulated email confirmation · door unlock | index.html (script) |
| `unlock.description` | 已建立只限這次虛擬門鎖解鎖的短效請求，有效至 {at}。先開啟下方模擬收件匣，再輸入訊息中的驗證碼。 | A short-lived request for this virtual door unlock only was created, valid until {at}. Open the simulated inbox below, then enter the code from the message. | index.html (script) |
| `unlock.alert` | 這是本機流程展示；沒有寄信、沒有連接實體門鎖。 | This is a local flow demo; no email is sent and no physical lock is connected. | index.html (script) |
| `unlock.codeLabel` | 本次短效驗證碼 | Short-lived code for this request | index.html (script) |
| `unlock.reveal` | 開啟模擬收件匣 | Open simulated inbox | index.html (script) |
| `unlock.inputLabel` | 輸入模擬郵件中的驗證碼 | Enter the code from the simulated email | index.html (script) |
| `unlock.confirm` | 透過 MCP 模擬解鎖 | Simulate unlock via MCP | index.html (script) |
| `unlock.noResult` | MCP 沒有回傳虛擬門鎖解鎖結果。 | MCP did not return a virtual door unlock result. | index.html (script) |
| `notice.mcpUnverified` | MCP 後端沒有回傳可驗證的模擬結果；不宣告動作成功。 | The MCP backend returned no verifiable simulated result; the action is not reported as successful. | index.html (script) |
| `notice.loggedOut` | 已登出。本頁沒有儲存登入權杖。 | Logged out. This page did not store the login token. | index.html (script) |
| `notice.scheduleCancelled` | 模擬排程已取消。 | Simulated schedule cancelled. | index.html (script) |
| `notice.paired` | {name}已完成模擬配對。 | {name}: simulated pairing complete. | index.html (script) |
| `notice.unlocked` | 門鎖已通過短效確認，MCP 回傳虛擬解鎖結果（模擬）。 | Door lock passed the short-lived confirmation; MCP returned a virtual unlock result (simulated). | index.html (script) |
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
