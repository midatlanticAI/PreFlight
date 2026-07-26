// Adversarial contextless suite, round 2: per-await rejection guarding.
//
// Four agents wrote these cases from a written spec alone. None of them could
// read the implementation or each other's work: two hunting false negatives,
// two hunting false positives, one of those attacking the parser rather than
// the logic. A fifth agent then adjudicated the combined set and found three
// contradictions where two authors demanded opposite behaviour from the same
// code shape.
//
// The round paid for itself. It found, in the implementation as first written:
//
//   - a `catch` clause being credited as a guard for its own awaits, which is
//     the same category error the change set out to fix, in different syntax
//   - `try { await x() } finally { … }` treated as handled, when finally runs
//     on the way past and the rejection keeps going
//   - `.catch` counted anywhere in a chain rather than at its tail, so
//     `await load().catch(h).then(normalize)` read as safe
//   - anonymous `async function () {}` callbacks never matched at all
//   - TypeScript arrows with a return-type annotation never matched either
//   - two false positives in the neighbouring bare-async-call check, where a
//     formatter-wrapped chain puts `send()` alone on its line and the handler
//     two lines below
//
// Adjudicated changes to the authored set, recorded so the reasoning survives:
//   - "catch block awaits an error reporter" flipped to FIRE. A catch handles
//     the try block's failure, not its own.
//   - "catch clause rethrows the error" flipped to QUIET. Spotting a rethrow
//     needs flow analysis this rule deliberately does not do.
//   - "awaiting a promise variable .catch-chained at creation" dropped. It
//     asserts precision the rule does not promise, since it would require
//     following a binding back to its initializer.

import { describe, it, expect } from 'vitest';
import { probeCodeQuality } from '../lib/probes/quality.js';

const RELEVANT = /fire-and-forget|try\/catch/i;

function findings(path, content) {
  return probeCodeQuality([{ path, content }]).filter((f) => RELEVANT.test(f.title));
}

// Each fixture is compiled as its own module: several reuse top-level const
// names, which the adjudicator flagged as a collision hazard if concatenated.
const CASES = [
  {
    name: 'fires when .catch() guards the json() promise but not the awaited fetch (anchor defect)',
    fire: true,
    ext: 'js',
    code: "const $ = (id) => document.getElementById(id);\n\n$('pwSave').addEventListener('click', async () => {\n  const body = { current: $('pwCur').value, next: $('pwNew').value };\n  const r = await fetch('/api/auth/password', {\n    method: 'POST',\n    headers: { 'Content-Type': 'application/json' },\n    body: JSON.stringify(body),\n  });\n  const j = await r.json().catch(() => ({}));\n  $('pwMsg').textContent = j.error ? j.error : 'Password updated';\n});\n",
  },
  {
    name: 'fires when a try block covers the first await but a later await sits outside it',
    fire: true,
    ext: 'js',
    code: "document.getElementById('sync').addEventListener('click', async () => {\n  let profile;\n  try {\n    profile = await loadProfile();\n  } catch (err) {\n    console.error('profile load failed', err);\n    return;\n  }\n  const settings = await loadSettings(profile.id);\n  renderSettings(settings);\n});\n",
  },
  {
    name: 'fires when several awaits precede a single guarded final await',
    fire: true,
    ext: 'js',
    code: "setTimeout(async () => {\n  const token = await refreshToken();\n  const session = await openSession(token);\n  session.attach(document.body);\n  await session.flush().catch((e) => console.warn('flush failed', e));\n}, 5000);\n",
  },
  {
    name: 'fires for setInterval with an await ending in .then and no catch',
    fire: true,
    ext: 'js',
    code: "setInterval(async () => {\n  const stats = await fetch('/api/metrics').then((r) => r.json());\n  document.getElementById('cpu').textContent = stats.cpu + '%';\n  document.getElementById('mem').textContent = stats.mem + ' MB';\n}, 15000);\n",
  },
  {
    name: 'fires for setImmediate with awaits in a loop and no handler',
    fire: true,
    ext: 'js',
    code: "setImmediate(async () => {\n  const rows = await db.query('SELECT id FROM jobs WHERE state = $1', ['queued']);\n  for (const row of rows) {\n    await queue.push(row.id);\n  }\n  logger.info('enqueued %d jobs', rows.length);\n});\n",
  },
  {
    name: 'fires for a JSX onClick async arrow that throws on a bad response',
    fire: true,
    ext: 'jsx',
    code: 'export function DeleteButton({ id, onDone }) {\n  return (\n    <button\n      className="danger"\n      onClick={async () => {\n        const res = await fetch(`/api/items/${id}`, { method: \'DELETE\' });\n        if (!res.ok) {\n          throw new Error(`delete failed: ${res.status}`);\n        }\n        onDone(id);\n      }}\n    >\n      Delete\n    </button>\n  );\n}\n',
  },
  {
    name: 'fires for JSX onSubmit where .catch is on response.json() only',
    fire: true,
    ext: 'jsx',
    code: "import React from 'react';\n\nexport default function LoginForm() {\n  const [msg, setMsg] = React.useState('');\n  return (\n    <form\n      onSubmit={async (e) => {\n        e.preventDefault();\n        const res = await fetch('/api/login', {\n          method: 'POST',\n          body: new FormData(e.currentTarget),\n        });\n        const data = await res.json().catch(() => ({}));\n        setMsg(data.error || 'Signed in');\n      }}\n    >\n      <button type=\"submit\">Sign in</button>\n    </form>\n  );\n}\n",
  },
  {
    name: 'fires for a JSX onChange async function expression',
    fire: true,
    ext: 'jsx',
    code: "export function Uploader({ onUploaded }) {\n  return (\n    <input\n      type=\"file\"\n      onChange={async function (event) {\n        const file = event.target.files[0];\n        if (!file) return;\n        const form = new FormData();\n        form.append('file', file);\n        const res = await fetch('/api/upload', { method: 'POST', body: form });\n        onUploaded(await res.json());\n      }}\n    />\n  );\n}\n",
  },
  {
    name: 'fires for addEventListener with an async function expression callback',
    fire: true,
    ext: 'js',
    code: "window.addEventListener('online', async function () {\n  const pending = readOutbox();\n  for (const item of pending) {\n    await fetch('/api/outbox', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify(item),\n    });\n  }\n  clearOutbox();\n});\n",
  },
  {
    name: "fires when .catch is an inner link of a chain rather than the chain's tail",
    fire: true,
    ext: 'js',
    code: "document.querySelector('#refresh').addEventListener('click', async () => {\n  const user = await loadUser()\n    .catch(() => null)\n    .then((u) => normalize(u));\n  renderProfile(user);\n});\n",
  },
  {
    name: 'fires when a rejected element is hidden inside Promise.all with a catch on a sibling',
    fire: true,
    ext: 'js',
    code: "setInterval(async () => {\n  const [users, orders] = await Promise.all([\n    fetch('/api/users').then((r) => r.json()).catch(() => []),\n    fetch('/api/orders').then((r) => r.json()),\n  ]);\n  updateDashboard(users, orders);\n}, 30000);\n",
  },
  {
    name: 'fires when the only handler is .finally(), which does not handle rejection',
    fire: true,
    ext: 'js',
    code: "setTimeout(async () => {\n  showSpinner();\n  await syncAll({ full: true }).finally(() => hideSpinner());\n  toast('Sync complete');\n}, 0);\n",
  },
  {
    name: 'fires when the try/catch belongs to a nested helper, not the outer callback',
    fire: true,
    ext: 'js',
    code: "document.getElementById('open').addEventListener('click', async () => {\n  const report = async (evt) => {\n    try {\n      await fetch('/api/telemetry', { method: 'POST', body: JSON.stringify(evt) });\n    } catch (e) {\n      console.warn('telemetry dropped', e);\n    }\n  };\n  const data = await fetch('/api/report').then((r) => r.json());\n  report({ kind: 'viewed', rows: data.rows.length });\n});\n",
  },
  {
    name: "fires when 'try {' and '.catch(' appear only in a comment and a string literal",
    fire: true,
    ext: 'js',
    code: "setTimeout(async () => {\n  // TODO: wrap this in try { ... } catch and add a .catch( handler\n  const hint = 'always use .catch( on promises; try { } is better than nothing';\n  const cfg = await fetch('/config.json').then((r) => r.json());\n  applyConfig(cfg);\n  console.debug(hint);\n}, 250);\n",
  },
  {
    name: 'fires for an await inside the catch block, which is outside the try block',
    fire: true,
    ext: 'js',
    code: "form.addEventListener('submit', async (e) => {\n  e.preventDefault();\n  try {\n    await saveDraft(new FormData(form));\n    show('Saved');\n  } catch (err) {\n    await fetch('/api/errors', {\n      method: 'POST',\n      body: JSON.stringify({ message: err.message }),\n    });\n    show('Save failed');\n  }\n});\n",
  },
  {
    name: "fires when a try guards only a nested forEach callback's await",
    fire: true,
    ext: 'js',
    code: "list.addEventListener('change', async (e) => {\n  const ids = selectedIds(e.target);\n  ids.forEach(async (id) => {\n    try {\n      await prefetch(id);\n    } catch {\n      /* best effort */\n    }\n  });\n  const summary = await fetch('/api/summary?ids=' + ids.join(',')).then((r) => r.json());\n  paintSummary(summary);\n});\n",
  },
  {
    name: 'fires when a guarded await precedes an unguarded await inside a pagination loop',
    fire: true,
    ext: 'js',
    code: "document.addEventListener('visibilitychange', async () => {\n  if (document.hidden) return;\n  await heartbeat().catch(() => {});\n  let cursor = null;\n  do {\n    const page = await fetchPage(cursor);\n    appendRows(page.items);\n    cursor = page.next;\n  } while (cursor);\n});\n",
  },
  {
    name: 'fires for a JSX onKeyDown async handler with two unguarded awaits',
    fire: true,
    ext: 'jsx',
    code: 'export function SearchBox({ onResults }) {\n  return (\n    <input\n      type="search"\n      placeholder="Search orders"\n      onKeyDown={async (e) => {\n        if (e.key !== \'Enter\') return;\n        const res = await fetch(\'/api/search?q=\' + encodeURIComponent(e.target.value));\n        const body = await res.json();\n        onResults(body.hits);\n      }}\n    />\n  );\n}\n',
  },
  {
    name: 'fires on unguarded await inside a for-of loop in a click listener',
    fire: true,
    ext: 'js',
    code: "const list = document.getElementById('refreshAll');\nlist.addEventListener('click', async () => {\n  const ids = collectSelectedIds();\n  const results = [];\n  for (const id of ids) {\n    const res = await fetch(`/api/items/${id}/refresh`, { method: 'POST' });\n    results.push(await res.json());\n  }\n  renderResults(results);\n});\n",
  },
  {
    name: 'fires on unguarded awaits split across if/else-if/else branches in setTimeout',
    fire: true,
    ext: 'js',
    code: "setTimeout(async () => {\n  const mode = window.localStorage.getItem('sync-mode');\n  if (mode === 'full') {\n    await syncEverything({ force: true });\n  } else if (mode === 'delta') {\n    await syncSince(lastSyncedAt);\n  } else {\n    await pingServer();\n  }\n  markSyncComplete();\n}, 5000);\n",
  },
  {
    name: 'fires on unguarded awaits in switch arms of a JSX onClick handler',
    fire: true,
    ext: 'jsx',
    code: "export function ToolbarButton({ action, doc }) {\n  return (\n    <button\n      onClick={async () => {\n        switch (action) {\n          case 'save':\n            await doc.save();\n            break;\n          case 'publish':\n            await doc.publish({ notify: true });\n            break;\n          default:\n            await doc.reload();\n        }\n        toast(`${action} done`);\n      }}\n    >\n      {action}\n    </button>\n  );\n}\n",
  },
  {
    name: 'fires on await inside a bare nested block that is not a try',
    fire: true,
    ext: 'js',
    code: "document.querySelector('#exportBtn').addEventListener('click', async (event) => {\n  event.preventDefault();\n  {\n    const blob = await buildExportBlob(currentProjectId);\n    downloadBlob(blob, 'export.zip');\n  }\n});\n",
  },
  {
    name: 'fires on try/finally with no catch clause',
    fire: true,
    ext: 'js',
    code: "saveButton.addEventListener('click', async () => {\n  setBusy(true);\n  try {\n    const payload = serializeForm(document.forms.settings);\n    await fetch('/api/settings', {\n      method: 'PUT',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify(payload),\n    });\n  } finally {\n    setBusy(false);\n  }\n});\n",
  },
  {
    name: 'fires when the catch clause rethrows the error',
    fire: false,
    ext: 'js',
    code: "form.addEventListener('submit', async (e) => {\n  e.preventDefault();\n  try {\n    await submitOrder(readOrderForm(e.target));\n  } catch (err) {\n    reportToTelemetry(err);\n    throw err;\n  }\n  showConfirmation();\n});\n",
  },
  {
    name: 'fires when only a nested helper function has try/catch',
    fire: true,
    ext: 'js',
    code: "window.addEventListener('online', async () => {\n  async function flushOne(item) {\n    try {\n      await api.upload(item);\n    } catch (err) {\n      queue.requeue(item, err);\n    }\n  }\n  const pending = await queue.drain();\n  await Promise.all(pending.map(flushOne));\n});\n",
  },
  {
    name: 'fires on await Promise.all([...]) with no catch',
    fire: true,
    ext: 'js',
    code: "refreshBtn.addEventListener('click', async () => {\n  const [profile, invoices, usage] = await Promise.all([\n    fetchProfile(userId),\n    fetchInvoices(userId, { limit: 20 }),\n    fetchUsage(userId),\n  ]);\n  renderDashboard({ profile, invoices, usage });\n});\n",
  },
  {
    name: 'fires on for-await-of over a stream with no guard',
    fire: true,
    ext: 'js',
    code: "startBtn.addEventListener('click', async () => {\n  const response = await fetch('/api/logs/stream');\n  const decoder = new TextDecoder();\n  for await (const chunk of response.body) {\n    appendLogChunk(decoder.decode(chunk, { stream: true }));\n  }\n  markStreamClosed();\n});\n",
  },
  {
    name: 'fires on a deeply indented awaited expression spanning many lines',
    fire: true,
    ext: 'js',
    code: "setTimeout(async () => {\n  const report = await generateReport({\n    projectId: currentProject.id,\n    range: {\n      from: startOfMonth(new Date()),\n      to: new Date(),\n    },\n    includeArchived: false,\n    format: 'pdf',\n  });\n  renderReport(report);\n}, 250);\n",
  },
  {
    name: 'fires on TypeScript callback with generics, casts and non-null assertion',
    fire: true,
    ext: 'ts',
    code: "const btn = document.getElementById('load') as HTMLButtonElement;\nbtn.addEventListener('click', async (ev: MouseEvent): Promise<void> => {\n  ev.preventDefault();\n  const res = await httpGet<ApiResponse<User[]>>(`/api/users?page=${page}`);\n  const users: User[] = res.data!.items;\n  renderUserTable(users);\n});\n",
  },
  {
    name: 'fires on await inside a while loop in setInterval',
    fire: true,
    ext: 'js',
    code: "setInterval(async () => {\n  let cursor = jobQueue.head();\n  while (cursor) {\n    const job = await jobQueue.claim(cursor);\n    if (job) {\n      await runJob(job);\n    }\n    cursor = jobQueue.next(cursor);\n  }\n  metrics.gauge('queue.depth', jobQueue.size());\n}, 30000);\n",
  },
  {
    name: 'fires when the try block covers only validation and the await sits after it',
    fire: true,
    ext: 'js',
    code: "document.getElementById('pwSave').addEventListener('click', async () => {\n  const current = currentPasswordInput.value;\n  try {\n    validatePasswordPolicy(newPasswordInput.value);\n  } catch (err) {\n    showFieldError(err.message);\n    return;\n  }\n  const res = await fetch('/api/auth/password', {\n    method: 'POST',\n    body: JSON.stringify({ current, next: newPasswordInput.value }),\n  });\n  showToast(res.ok ? 'Password updated' : 'Update failed');\n});\n",
  },
  {
    name: 'fires when one await has .catch() and a sibling await in the same loop does not',
    fire: true,
    ext: 'js',
    code: "uploadDrop.addEventListener('drop', async (event) => {\n  event.preventDefault();\n  const files = Array.from(event.dataTransfer.files);\n  for (const file of files) {\n    const signed = await requestUploadUrl(file.name).catch(() => null);\n    if (!signed) continue;\n    await fetch(signed.url, { method: 'PUT', body: file });\n  }\n  refreshFileList();\n});\n",
  },
  {
    name: 'fires despite decoy try and .catch text in comments and string literals',
    fire: true,
    ext: 'js',
    code: "// TODO: wrap this in try { } and add a .catch( ) before launch\nnavigator.serviceWorker.addEventListener('message', async (event) => {\n  const label = 'retry with .catch( ) fallback';\n  const detail = `try { ${event.data.kind} } // handled elsewhere`;\n  const record = await db.records.get(event.data.id);\n  logSync(label, detail, record);\n});\n",
  },
  {
    name: 'fires on awaited conditional expression plus optional-call await in setImmediate',
    fire: true,
    ext: 'js',
    code: "setImmediate(async () => {\n  const config = await (process.env.CONFIG_URL\n    ? fetchRemoteConfig(process.env.CONFIG_URL)\n    : loadLocalConfig());\n  await cache?.warm(config);\n  logger.info('config ready', { keys: Object.keys(config).length });\n});\n",
  },
  {
    name: 'fires when .catch() is nested inside the awaited expression rather than at its top level',
    fire: true,
    ext: 'js',
    code: "retryBtn.addEventListener('click', async () => {\n  const settled = await Promise.all([\n    syncContacts().catch(() => null),\n    syncCalendars().catch(() => null),\n  ]).then((r) => r.filter(Boolean));\n  await persistSyncState(settled);\n  renderSyncBadge(settled.length);\n});\n",
  },
  {
    name: 'fires on awaits in a JSX onChange handler nested inside an if branch',
    fire: true,
    ext: 'jsx',
    code: 'export default function AvatarPicker({ userId, onDone }) {\n  return (\n    <input\n      type="file"\n      accept="image/*"\n      onChange={async (e) => {\n        const file = e.target.files?.[0];\n        if (!file) return;\n        if (file.size > 5_000_000) {\n          await compressImage(file, { maxBytes: 5_000_000 });\n        }\n        const url = await uploadAvatar(userId, file);\n        onDone(url);\n      }}\n    />\n  );\n}\n',
  },
  {
    name: 'fires on async function expression callback with await inside a do-while',
    fire: true,
    ext: 'js',
    code: "socket.addEventListener('message', async function (event) {\n  let backoff = 100;\n  do {\n    const ack = await sendAck(event.data.id, { backoff });\n    if (ack.ok) break;\n    await delay(backoff);\n    backoff *= 2;\n  } while (backoff < 3200);\n  metrics.increment('ws.ack');\n});\n",
  },
  {
    name: 'does not fire when every await in a listener is individually .catch-chained',
    fire: false,
    ext: 'js',
    code: "const saveBtn = document.getElementById('save-profile');\n\nsaveBtn.addEventListener('click', async () => {\n  saveBtn.disabled = true;\n  const res = await fetch('/api/profile', {\n    method: 'PUT',\n    headers: { 'content-type': 'application/json' },\n    body: JSON.stringify({ name: saveBtn.dataset.name }),\n  }).catch(() => null);\n\n  if (!res || !res.ok) {\n    showToast('Could not save your profile');\n    saveBtn.disabled = false;\n    return;\n  }\n\n  const body = await res.json().catch(() => ({}));\n  showToast(body.message || 'Saved');\n  saveBtn.disabled = false;\n});\n",
  },
  {
    name: 'does not fire when the whole async listener body is wrapped in try/catch',
    fire: false,
    ext: 'js',
    code: "const form = document.querySelector('#login-form');\n\nform.addEventListener('submit', async (event) => {\n  event.preventDefault();\n  try {\n    const res = await fetch('/api/auth/login', {\n      method: 'POST',\n      body: new FormData(form),\n    });\n    const session = await res.json();\n    window.location.assign(session.redirectTo || '/dashboard');\n  } catch (err) {\n    console.error('login failed', err);\n    form.querySelector('.error').textContent = 'Login failed, try again.';\n  }\n});\n",
  },
  {
    name: 'does not fire for an async listener callback that contains no await',
    fire: false,
    ext: 'js',
    code: "let pending = null;\nconst layout = window.appLayout;\n\nwindow.addEventListener('resize', async () => {\n  if (pending) {\n    cancelAnimationFrame(pending);\n  }\n  pending = requestAnimationFrame(() => {\n    layout.reflow(window.innerWidth, window.innerHeight);\n  });\n});\n",
  },
  {
    name: 'does not fire for a plain async function declaration with unguarded awaits',
    fire: false,
    ext: 'jsx',
    code: "export async function loadInvoices(customerId) {\n  const res = await fetch(`/api/customers/${customerId}/invoices`);\n  if (!res.ok) {\n    throw new Error(`invoices request failed: ${res.status}`);\n  }\n  const { data } = await res.json();\n  return data.map((row) => ({ ...row, total: Number(row.total) }));\n}\n\nexport async function renderInvoices(customerId, mount) {\n  const invoices = await loadInvoices(customerId);\n  mount.innerHTML = invoices.map((i) => `<li>${i.number}</li>`).join('');\n}\n",
  },
  {
    name: 'does not fire for an async callback passed to a helper that awaits it',
    fire: false,
    ext: 'js',
    code: "async function withRetry(fn, attempts = 3) {\n  let lastError;\n  for (let i = 0; i < attempts; i += 1) {\n    try {\n      return await fn();\n    } catch (err) {\n      lastError = err;\n    }\n  }\n  throw lastError;\n}\n\nexport async function syncOrders(db) {\n  const orders = await withRetry(async () => {\n    const res = await fetch('/api/orders?status=open');\n    return res.json();\n  });\n  await db.orders.bulkPut(orders);\n  return orders.length;\n}\n",
  },
  {
    name: "does not fire when the catch block's own await is itself .catch-chained",
    fire: false,
    ext: 'js',
    code: "const uploadBtn = document.getElementById('upload');\n\nuploadBtn.addEventListener('click', async () => {\n  try {\n    const res = await fetch('/api/upload', { method: 'POST', body: currentFile() });\n    const json = await res.json();\n    setStatus(json.state);\n  } catch (err) {\n    await reportTelemetry({ event: 'upload_failed', message: err.message }).catch(() => {});\n    setStatus('failed');\n  }\n});\n",
  },
  {
    name: "does not fire when a try's catch block awaits an error reporter",
    fire: true,
    ext: 'js',
    code: "const uploadBtn = document.getElementById('upload-report');\n\nuploadBtn.addEventListener('click', async () => {\n  try {\n    const res = await fetch('/api/reports', { method: 'POST', body: buildReport() });\n    const json = await res.json();\n    setStatus(json.state);\n  } catch (err) {\n    await reportTelemetry({ event: 'report_failed', message: err.message });\n    setStatus('failed');\n  }\n});\n",
  },
  {
    name: 'does not fire for nested try/catch inside an async listener',
    fire: false,
    ext: 'js',
    code: "document.getElementById('publish').addEventListener('click', async () => {\n  try {\n    const draft = await store.readDraft();\n    try {\n      await api.publish(draft);\n      toast('Published');\n    } catch (publishError) {\n      await store.markFailed(draft.id);\n      toast('Publish failed, kept a local copy');\n    }\n  } catch (readError) {\n    toast('Could not read your draft');\n  }\n});\n",
  },
  {
    name: 'does not fire for a named async function reference passed to addEventListener',
    fire: false,
    ext: 'js',
    code: "async function handleSubscribe(event) {\n  event.preventDefault();\n  const email = event.target.elements.email.value;\n  try {\n    const res = await fetch('/api/subscribe', {\n      method: 'POST',\n      headers: { 'content-type': 'application/json' },\n      body: JSON.stringify({ email }),\n    });\n    const body = await res.json();\n    renderResult(body.ok ? 'Check your inbox' : body.error);\n  } catch (err) {\n    renderResult('Network error, please retry');\n  }\n}\n\ndocument.getElementById('subscribe-form').addEventListener('submit', handleSubscribe);\n",
  },
  {
    name: 'does not fire for a JSX onClick async handler with try/catch/finally',
    fire: false,
    ext: 'jsx',
    code: "import { useState } from 'react';\n\nexport function DeleteButton({ id, onDeleted }) {\n  const [busy, setBusy] = useState(false);\n  return (\n    <button\n      type=\"button\"\n      disabled={busy}\n      onClick={async () => {\n        setBusy(true);\n        try {\n          await api.delete(`/documents/${id}`);\n          onDeleted(id);\n        } catch (err) {\n          toast.error('Delete failed');\n        } finally {\n          setBusy(false);\n        }\n      }}\n    >\n      Delete\n    </button>\n  );\n}\n",
  },
  {
    name: 'does not fire for a JSX onChange async handler with every await .catch-chained',
    fire: false,
    ext: 'jsx',
    code: 'export function CityPicker({ onPick }) {\n  return (\n    <input\n      type="search"\n      placeholder="City"\n      onChange={async (event) => {\n        const q = event.target.value.trim();\n        if (q.length < 3) return;\n        const res = await fetch(`/api/cities?q=${encodeURIComponent(q)}`).catch(() => null);\n        if (!res || !res.ok) return;\n        const cities = await res.json().catch(() => []);\n        onPick(cities.slice(0, 8));\n      }}\n    />\n  );\n}\n',
  },
  {
    name: 'does not fire when await appears only in comments and string literals',
    fire: false,
    ext: 'js',
    code: "const searchInput = document.getElementById('site-search');\n\nsearchInput.addEventListener('input', async (event) => {\n  // await fetch('/api/search') here would fire on every keystroke; we debounce instead\n  const query = event.target.value.trim();\n  const hint = `await fetch('/api/search?q=${encodeURIComponent(query)}')`;\n  if (window.DEBUG) {\n    debugPanel.textContent = hint + \" -- await res.json() deferred\";\n  }\n  scheduleSearch(query);\n});\n",
  },
  {
    name: 'does not fire when the only awaits belong to a nested function whose promise is .catch-chained',
    fire: false,
    ext: 'js',
    code: "const socket = new EventSource('/api/stream');\n\nsocket.addEventListener('message', async (evt) => {\n  async function persist(payload) {\n    const res = await fetch('/api/events', {\n      method: 'POST',\n      headers: { 'content-type': 'application/json' },\n      body: JSON.stringify(payload),\n    });\n    return res.ok;\n  }\n\n  const payload = JSON.parse(evt.data);\n  renderRow(payload);\n  persist(payload).catch((err) => console.warn('persist failed', err));\n});\n",
  },
  {
    name: 'does not fire for an async arrow stored in a const and awaited by its caller',
    fire: false,
    ext: 'js',
    code: 'const loadDashboard = async (userId) => {\n  const [profile, stats] = await Promise.all([\n    fetch(`/api/users/${userId}`).then((r) => r.json()),\n    fetch(`/api/users/${userId}/stats`).then((r) => r.json()),\n  ]);\n  return { profile, stats };\n};\n\nexport async function bootstrap(userId, view) {\n  const data = await loadDashboard(userId);\n  view.render(data);\n}\n',
  },
  {
    name: 'does not fire for an async IIFE inside a sync listener with .catch on the call',
    fire: false,
    ext: 'js',
    code: "document.getElementById('export-csv').addEventListener('click', () => {\n  (async () => {\n    const res = await fetch('/api/export', { method: 'POST' });\n    const blob = await res.blob();\n    downloadBlob(blob, 'export.csv');\n  })().catch((err) => notify('Export failed', err));\n});\n",
  },
  {
    name: 'does not fire for setInterval whose awaited Promise.all is .catch-chained',
    fire: false,
    ext: 'js',
    code: "const statusEl = document.getElementById('ops-status');\n\nsetInterval(async () => {\n  const [health, queue] = await Promise.all([\n    fetch('/api/health').then((r) => r.json()),\n    fetch('/api/queue').then((r) => r.json()),\n  ]).catch(() => [null, null]);\n\n  if (!health || !queue) {\n    statusEl.textContent = 'metrics unavailable';\n    return;\n  }\n  statusEl.textContent = `${health.state} / ${queue.depth} queued`;\n}, 15000);\n",
  },
  {
    name: 'does not fire for a non-async JSX submit handler that .catch-chains the async call',
    fire: false,
    ext: 'jsx',
    code: 'export function OrderForm({ payload, onError }) {\n  return (\n    <form\n      onSubmit={(event) => {\n        event.preventDefault();\n        submitOrder(payload)\n          .then((order) => trackConversion(order.id))\n          .catch(onError);\n      }}\n    >\n      <button type="submit">Place order</button>\n    </form>\n  );\n}\n',
  },
  {
    name: 'does not fire for a for-await loop wrapped in try/catch inside a listener',
    fire: false,
    ext: 'js',
    code: "const source = new EventSource('/api/updates');\n\nsource.addEventListener('open', async () => {\n  try {\n    for await (const chunk of streamUpdates(source)) {\n      appendRow(chunk);\n    }\n    setStatus('stream closed cleanly');\n  } catch (err) {\n    console.warn('stream ended unexpectedly', err);\n    setStatus('reconnecting');\n    scheduleReconnect();\n  }\n});\n",
  },
  {
    name: "does not fire when a nested async map callback's awaits are collected into a guarded await",
    fire: false,
    ext: 'js',
    code: "dropZone.addEventListener('drop', async (event) => {\n  event.preventDefault();\n  try {\n    const files = Array.from(event.dataTransfer.files);\n    const results = await uploadAll(files);\n    renderUploads(results);\n  } catch (err) {\n    toast('Upload failed, nothing was saved');\n  }\n\n  function uploadAll(list) {\n    return Promise.all(\n      list.map(async (file) => {\n        const res = await fetch('/api/files', { method: 'POST', body: file });\n        return res.json();\n      }),\n    );\n  }\n});\n",
  },
  {
    name: 'does not fire for await/fetch and listener code that only appears in string literals, template literals, and comments',
    fire: false,
    ext: 'js',
    code: "// Docs sample: el.addEventListener('click', async () => { await fetch('/api/save'); });\nconst SNIPPETS = {\n  listener: \"el.addEventListener('click', async () => { await fetch('/api/save'); })\",\n  timer: `setTimeout(async () => {\n    await fetch('/api/ping');\n  }, 1000)`,\n};\n\nexport function renderSnippet(key) {\n  const src = SNIPPETS[key];\n  if (!src) return '<p>Unknown snippet</p>';\n  const escaped = src.replace(/&/g, '&amp;').replace(/</g, '&lt;');\n  return '<pre><code>' + escaped + '</code></pre>';\n}\n\nexport function snippetKeys() {\n  return Object.keys(SNIPPETS);\n}\n",
  },
  {
    name: 'does not fire when an async listener example lives only in a JSDoc @example block',
    fire: false,
    ext: 'js',
    code: "/**\n * Wire up the profile form.\n *\n * @example\n * form.addEventListener('submit', async (event) => {\n *   event.preventDefault();\n *   await api.saveProfile(new FormData(event.target));\n * });\n */\nexport function attachProfileForm(form, api, toast) {\n  form.addEventListener('submit', (event) => {\n    event.preventDefault();\n    api\n      .saveProfile(new FormData(event.target))\n      .then(() => toast('Profile saved'))\n      .catch((err) => toast('Save failed: ' + err.message));\n  });\n}\n",
  },
  {
    name: 'does not fire on template literals containing braces and escaped backticks near a non-async listener',
    fire: false,
    ext: 'js',
    code: "const users = [];\n\nexport function buildRow(user) {\n  const badge = user.admin ? `{admin}` : `{user}`;\n  return `\n    <tr data-id=\"${user.id}\">\n      <td>${user.name} } </td>\n      <td>${`\\`${badge}\\``}</td>\n    </tr>`;\n}\n\ndocument.addEventListener('DOMContentLoaded', () => {\n  const tbody = document.querySelector('#users tbody');\n  if (!tbody) return;\n  for (const u of users) {\n    tbody.insertAdjacentHTML('beforeend', buildRow(u));\n  }\n});\n",
  },
  {
    name: "does not fire on regex literals containing braces, quotes, and the literal text 'await'",
    fire: false,
    ext: 'js',
    code: "const AWAIT_CALL = /await\\s+fetch\\(\\s*['\"][^'\"]*['\"]\\s*\\)\\s*\\{?/g;\nconst BRACE_PAIR = /\\{[^}]*\\}/g;\n\nexport function countAwaitCalls(source) {\n  return (source.match(AWAIT_CALL) || []).length;\n}\n\nexport function stripBlocks(source) {\n  return source.replace(BRACE_PAIR, '{}');\n}\n\nwindow.addEventListener('load', () => {\n  const pre = document.getElementById('source');\n  const out = document.getElementById('count');\n  if (pre && out) out.textContent = String(countAwaitCalls(pre.textContent));\n});\n",
  },
  {
    name: 'does not fire on an object literal with try/catch/finally as property names',
    fire: false,
    ext: 'js',
    code: "const lifecycle = {\n  try: (fn) => fn(),\n  catch: (err) => console.error('[lifecycle]', err),\n  finally: () => performance.mark('lifecycle:end'),\n};\n\nexport function runStep(fn) {\n  try {\n    return lifecycle.try(fn);\n  } catch (err) {\n    lifecycle.catch(err);\n    return null;\n  } finally {\n    lifecycle.finally();\n  }\n}\n\nsetInterval(() => {\n  runStep(() => {\n    document.body.dataset.heartbeat = String(Date.now());\n  });\n}, 15000);\n",
  },
  {
    name: 'does not fire on brace-bearing string constants next to a plain async function declaration',
    fire: false,
    ext: 'js',
    code: "const OPEN_BRACE = '{';\nconst CLOSE_BRACE = '}';\n\nexport async function loadTemplate(name) {\n  const res = await fetch(`/templates/${name}.html`);\n  if (!res.ok) throw new Error('template ' + name + ' missing');\n  return res.text();\n}\n\nexport function interpolate(tpl, data) {\n  return tpl.replace(/\\{\\{(\\w+)\\}\\}/g, (_, key) =>\n    data[key] == null ? OPEN_BRACE + key + CLOSE_BRACE : String(data[key]),\n  );\n}\n\ndocument.getElementById('reload').addEventListener('click', () => {\n  loadTemplate('invoice')\n    .then((tpl) => document.getElementById('out').replaceChildren(tpl))\n    .catch((err) => console.error(err));\n});\n",
  },
  {
    name: "does not fire when a string containing '{' precedes a fully try-guarded async listener",
    fire: false,
    ext: 'js',
    code: "const LEFT = \"{\";\n\ndocument.getElementById('sync').addEventListener('click', async () => {\n  const label = LEFT + 'syncing' + '}';\n  try {\n    const res = await fetch('/api/sync', { method: 'POST' });\n    const body = await res.json();\n    setStatus(label, body.ok ? 'done' : 'failed');\n  } catch (err) {\n    setStatus(label, 'error: ' + err.message);\n  }\n});\n\nexport async function backgroundRefresh() {\n  const res = await fetch('/api/state');\n  return res.json();\n}\n\nfunction setStatus(label, text) {\n  document.getElementById('status').textContent = `${label} ${text}`;\n}\n",
  },
  {
    name: "does not fire when 'await' only appears as part of longer identifiers",
    fire: false,
    ext: 'js',
    code: "let awaitCount = 0;\nconst awaitable = { then: (resolve) => resolve(42) };\n\nfunction isAwaitable(value) {\n  return Boolean(value) && typeof value.then === 'function';\n}\n\ndocument.getElementById('probe').addEventListener('click', () => {\n  awaitCount += 1;\n  const myAwaitTarget = isAwaitable(awaitable) ? 'thenable' : 'plain';\n  document.getElementById('out').textContent = `${myAwaitTarget} #${awaitCount}`;\n});\n\nexport { isAwaitable };\n",
  },
  {
    name: 'does not fire when .catch is a method on a plain object rather than a promise',
    fire: false,
    ext: 'js',
    code: "const errorBus = {\n  handlers: [],\n  catch(fn) {\n    this.handlers.push(fn);\n    return this;\n  },\n  emit(err) {\n    this.handlers.forEach((fn) => fn(err));\n  },\n};\n\nfunction reportToUi(err) {\n  const banner = document.getElementById('banner');\n  if (banner) banner.textContent = err.message;\n}\n\nerrorBus.catch((err) => console.error('[bus]', err)).catch(reportToUi);\n\nsetInterval(() => {\n  if (navigator.onLine === false) errorBus.emit(new Error('offline'));\n}, 10000);\n",
  },
  {
    name: 'does not fire on JSX props that are not event handlers',
    fire: false,
    ext: 'jsx',
    code: 'import Preview from \'./Preview.jsx\';\n\nexport function ItemRow({ item, onSomething, formatter }) {\n  const label = formatter(item);\n  return (\n    <li className="row">\n      <Preview onSomething={formatter} onData={item.payload} onceLoaded={item.ready} />\n      <span>{label}</span>\n      <button type="button" onClick={() => onSomething(item.id)}>\n        Select\n      </button>\n    </li>\n  );\n}\n',
  },
  {
    name: 'does not fire when an async arrow is stored in a variable and attached later with full try/catch',
    fire: false,
    ext: 'js',
    code: "const handleSave = async (event) => {\n  event.preventDefault();\n  try {\n    const res = await fetch('/api/save', {\n      method: 'POST',\n      body: new FormData(event.target),\n    });\n    if (!res.ok) throw new Error('save failed with ' + res.status);\n    toast('Saved');\n  } catch (err) {\n    toast('Could not save: ' + err.message);\n  }\n};\n\nfunction toast(message) {\n  document.getElementById('toast').textContent = message;\n}\n\ndocument.getElementById('profile-form').addEventListener('submit', handleSave);\n",
  },
  {
    name: 'does not fire when the only unguarded await belongs to a nested async function inside a guarded callback',
    fire: false,
    ext: 'js',
    code: "window.addEventListener('online', async () => {\n  const queue = readQueue();\n  async function flushOne(item) {\n    const res = await fetch('/api/queue', {\n      method: 'POST',\n      body: JSON.stringify(item),\n    });\n    return res.ok;\n  }\n  try {\n    const results = await Promise.all(queue.map(flushOne));\n    clearQueue(results.filter(Boolean).length);\n  } catch (err) {\n    console.warn('queue flush failed', err);\n  }\n});\n\nfunction readQueue() {\n  return JSON.parse(localStorage.getItem('queue') || '[]');\n}\n\nfunction clearQueue(count) {\n  localStorage.setItem('queueFlushed', String(count));\n}\n",
  },
  {
    name: 'does not fire when a nested async helper is invoked with .then/.catch from a sync listener',
    fire: false,
    ext: 'js',
    code: "document.getElementById('upload').addEventListener('change', (event) => {\n  const file = event.target.files && event.target.files[0];\n  if (!file) return;\n\n  async function send() {\n    const res = await fetch('/api/upload', { method: 'POST', body: file });\n    if (!res.ok) throw new Error('upload rejected: ' + res.status);\n    return res.json();\n  }\n\n  send()\n    .then((result) => {\n      document.getElementById('upload-status').textContent = result.name;\n    })\n    .catch((err) => {\n      document.getElementById('upload-status').textContent = err.message;\n    });\n});\n",
  },
  {
    name: 'does not fire on a commented-out setInterval with an async callback',
    fire: false,
    ext: 'js',
    code: "// TODO(#412): re-enable health polling once the endpoint is rate limited.\n// setInterval(async () => {\n//   const res = await fetch('/api/health');\n//   updateBadge(await res.json());\n// }, 30000);\n\nexport function updateBadge(state) {\n  const el = document.getElementById('health-badge');\n  if (!el) return;\n  el.dataset.state = state.ok ? 'ok' : 'degraded';\n  el.textContent = state.ok ? 'Healthy' : 'Degraded';\n}\n\ndocument.addEventListener('DOMContentLoaded', () => {\n  updateBadge({ ok: true });\n});\n",
  },
  {
    name: 'does not fire when repeated division looks like a regex literal',
    fire: false,
    ext: 'js',
    code: "const routePattern = /\\/api\\/v1\\/(?:jobs|runs)\\/\\d+\\/?\\{?/;\n\nexport function throughput(total, seconds, workers) {\n  return total / seconds / workers;\n}\n\nexport function isJobRoute(pathname) {\n  return routePattern.test(pathname);\n}\n\nfunction refreshPanel() {\n  return fetch('/api/v1/jobs')\n    .then((r) => r.json())\n    .then((data) => {\n      document.getElementById('panel').textContent = JSON.stringify(data);\n    });\n}\n\ndocument.addEventListener('visibilitychange', () => {\n  if (document.hidden) return;\n  refreshPanel().catch((err) => console.warn('refresh failed', err));\n});\n",
  },
  {
    name: 'does not fire when setTimeout receives a string, not an async callback',
    fire: false,
    ext: 'js',
    code: 'const LEGACY_TICK = "window.vendorWidget && window.vendorWidget.refresh()";\nsetTimeout(LEGACY_TICK, 250);\n\nconst HANDLER_DOC = "async () => { await fetch(\'/api/legacy\'); }";\n\nexport function describeHandler() {\n  return `The vendor docs still show: ${HANDLER_DOC}`;\n}\n\nsetTimeout("console.warn(\'vendor widget did not load\')", 5000);\n',
  },
  {
    name: 'does not fire when a JSX handler prop references a guarded async function by name',
    fire: false,
    ext: 'jsx',
    code: "import { api } from './api.js';\n\nconst submitProfile = async (values) => {\n  try {\n    await api.saveProfile(values);\n    notify('Profile updated');\n  } catch (err) {\n    notify('Update failed: ' + err.message);\n  }\n};\n\nfunction notify(message) {\n  window.dispatchEvent(new CustomEvent('toast', { detail: message }));\n}\n\nexport function ProfileForm({ values, onSomething }) {\n  return (\n    <form onSubmit={submitProfile} onSomething={onSomething}>\n      <input name=\"email\" defaultValue={values.email} onChangeText={values.setEmail} />\n      <button type=\"submit\">Save</button>\n    </form>\n  );\n}\n",
  },
  {
    name: "does not fire when '.catch(' and 'await' appear inside a string in a fully guarded callback",
    fire: false,
    ext: 'js',
    code: "document.getElementById('export').addEventListener('click', async () => {\n  const note = 'if this fails we .catch( it and await a retry';\n  try {\n    const res = await fetch('/api/export');\n    if (!res.ok) throw new Error('export failed: ' + res.status);\n    const blob = await res.blob();\n    download(blob, 'export.csv');\n  } catch (err) {\n    alert(note + ' -> ' + err.message);\n  }\n});\n\nfunction download(blob, filename) {\n  const url = URL.createObjectURL(blob);\n  const a = document.createElement('a');\n  a.href = url;\n  a.download = filename;\n  a.click();\n  URL.revokeObjectURL(url);\n}\n",
  },
  {
    name: 'does not fire on module top-level await outside any callback',
    fire: false,
    ext: 'js',
    code: "const res = await fetch('/config.json');\nexport const config = await res.json();\n\nexport function applyFlags(flags) {\n  for (const [key, on] of Object.entries(flags)) {\n    document.documentElement.classList.toggle(`flag-${key}`, Boolean(on));\n  }\n}\n\ndocument.addEventListener('DOMContentLoaded', () => {\n  applyFlags(config.flags || {});\n});\n",
  },
  {
    name: 'does not fire for async callbacks in fire-and-forget position that contain no await',
    fire: false,
    ext: 'js',
    code: "const queue = [];\nconst socket = new WebSocket('wss://example.test/stream');\n\nsocket.addEventListener('message', async (event) => {\n  const payload = JSON.parse(event.data);\n  queue.push(payload);\n  scheduleDrain();\n});\n\nsetTimeout(async () => {\n  document.getElementById('status').textContent = `queued: ${queue.length}`;\n}, 1000);\n\nfunction scheduleDrain() {\n  if (queue.length >= 25) drain(queue.splice(0, 25));\n}\n\nfunction drain(batch) {\n  navigator.sendBeacon('/api/ingest', JSON.stringify(batch));\n}\n",
  },
];

describe('adversarial round 2: cases that must fire', () => {
  CASES.filter((c) => c.fire).forEach((c, i) => {
    it(c.name, () => {
      expect(findings(`src/adv-fire-${i}.${c.ext}`, c.code).length).toBeGreaterThan(0);
    });
  });
});

describe('adversarial round 2: cases that must stay quiet', () => {
  CASES.filter((c) => !c.fire).forEach((c, i) => {
    it(c.name, () => {
      expect(findings(`src/adv-quiet-${i}.${c.ext}`, c.code)).toEqual([]);
    });
  });
});
