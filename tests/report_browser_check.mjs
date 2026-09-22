// Optional real-browser verification through local Chromium's DevTools protocol.
// No browser library, model endpoint, or application server is needed.
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const base = process.env.CODE_ANALYZER_CDP_URL;
const page = await (await fetch(`${base}/json/new?${encodeURIComponent(pathToFileURL(process.argv[2]).href)}`, { method: "PUT" })).json();
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let sequence = 0;
const pending = new Map();
socket.onmessage = event => {
  const message = JSON.parse(event.data);
  const waiter = pending.get(message.id);
  if (waiter) {
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
    else waiter.resolve(message.result);
  }
};
const call = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++sequence;
  pending.set(id, { resolve, reject });
  socket.send(JSON.stringify({ id, method, params }));
});
const evaluate = async expression => {
  const result = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  assert.equal(result.exceptionDetails, undefined, JSON.stringify(result.exceptionDetails));
  return result.result.value;
};

try {
  await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  let ready = false;
  for (let i = 0; i < 100; i++) {
    ready = await evaluate('Boolean(document.querySelector("#finding-body tr"))');
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert(ready, "report initialization timed out");
  await evaluate('if (document.documentElement.lang !== "zh-CN") document.querySelector("#lang-toggle").click()');
  assert.equal(await evaluate('document.querySelector("#dashboard-error")?.textContent'), undefined);
  assert.equal(await evaluate('window.reportInjected'), undefined);
  assert.equal(await evaluate('document.querySelector("#context").value'), "");
  assert.match(await evaluate('document.querySelector("#finding-total").textContent'), /2,011.*2,000.*2,000/);
  assert.match(await evaluate('document.querySelector("#ai-summary").textContent'), /fixture opinion/);
  assert.match(await evaluate('document.querySelector("#candidate-body details").textContent'), /Short rationale/);
  assert.equal(await evaluate('document.querySelectorAll("#candidate-body > tr:not(.evidence-detail)").length'), 25);

  // A candidate overrides conflicting filters; returning restores them.
  const navigation = await evaluate(`(() => {
    const search = document.querySelector("#search");
    search.value = "does-not-exist"; search.dispatchEvent(new Event("input"));
    document.querySelector("#candidate-body > tr:not(.evidence-detail) button").click();
    const result = {search:search.value, rows:document.querySelectorAll("#finding-body details").length,
      notice:document.querySelector("#relation-notice").textContent};
    document.querySelector("#relation-notice button").click();
    result.restored = search.value;
    return result;
  })()`);
  assert.equal(navigation.search, "");
  assert.equal(navigation.rows, 1);
  assert.match(navigation.notice, /static-2005/);
  assert.equal(navigation.restored, "does-not-exist");

  // Reverse navigation reaches a candidate outside the current candidate page.
  assert.equal(await evaluate(`(() => {
    document.querySelector("#reset").click();
    const buttons = [...document.querySelectorAll("#finding-body .evidence-detail button")];
    buttons.find(button => button.textContent.includes("MEM-059")).click();
    return document.querySelector("#candidate-MEM-059").open;
  })()`), true);

  // Printing expands both paginated tables and restores pages/expanded rows.
  const printing = await evaluate(`(() => {
    const search=document.querySelector("#search");search.value="auditprint";search.dispatchEvent(new Event("input"));
    document.querySelector("#finding-body details").open=true;
    const before={rows:document.querySelectorAll("#finding-body details").length,
      candidatePage:document.querySelector("#candidate-page-status").textContent};
    window.dispatchEvent(new Event("beforeprint"));
    const during={rows:document.querySelectorAll("#finding-body details").length,
      candidates:document.querySelectorAll("#candidate-body details").length,
      closed:document.querySelectorAll("details:not([open])").length};
    window.dispatchEvent(new Event("afterprint"));
    const after={rows:document.querySelectorAll("#finding-body details").length,
      open:document.querySelectorAll("#finding-body details[open]").length,
      candidatePage:document.querySelector("#candidate-page-status").textContent};
    return {before,during,after};
  })()`);
  assert.equal(printing.before.rows, 50);
  assert.deepEqual(printing.during, { rows: 70, candidates: 60, closed: 0 });
  assert.equal(printing.after.rows, 50);
  assert.equal(printing.after.open, 1);
  assert.equal(printing.after.candidatePage, printing.before.candidatePage);

  await evaluate('document.querySelector("#lang-toggle").click()');
  assert.equal(await evaluate('document.documentElement.lang'), "en");
  assert.match(await evaluate('document.querySelector("#finding-total").textContent'), /Total 2,011.*Embedded 2,000.*Matching 70/);
  await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, "mobile page overflows");
  assert.equal(await evaluate('document.querySelector("#dashboard-error")?.textContent'), undefined);
  console.log("Verified counts, missing evidence, navigation, print restoration, bilingual UI, and mobile width.");
} finally {
  socket.close();
  await fetch(`${base}/json/close/${page.id}`);
}
