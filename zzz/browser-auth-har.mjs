import { mkdirSync, writeFileSync } from "node:fs";

const phone = "636025908";
const cdp = "http://127.0.0.1:19999";
const startURL = "https://cloud.o2online.es/ui/html/mobileconnect.html#start";
const outDir = new URL("./out/", import.meta.url);

class CDP {
  constructor(wsURL) {
    this.ws = new WebSocket(wsURL);
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    this.ready = new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      }
      if (msg.method && this.handlers.has(msg.method)) {
        for (const handler of this.handlers.get(msg.method)) handler(msg.params ?? {});
      }
    };
  }

  async send(method, params = {}) {
    await this.ready;
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => reject(new Error(`Timeout ${method}`)), 20000);
    });
  }

  on(method, handler) {
    if (!this.handlers.has(method)) this.handlers.set(method, new Set());
    this.handlers.get(method).add(handler);
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function openPage(url) {
  const page = await fetch(`${cdp}/json/new?${encodeURIComponent(url)}`, { method: "PUT" }).then((r) => r.json());
  return new CDP(page.webSocketDebuggerUrl);
}

async function pageByTitle(title) {
  const pages = await fetch(`${cdp}/json/list`).then((r) => r.json());
  const page = pages.find((item) => item.title.includes(title));
  return new CDP(page.webSocketDebuggerUrl);
}

async function value(page, expression) {
  const result = await page.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  return result.result.value;
}

async function latestSMS() {
  const sms = await pageByTitle("httpSMS");
  await sms.send("Page.enable");
  await sms.send("Runtime.enable");
  await sms.send("Page.reload", { ignoreCache: true });
  await sleep(5000);
  const text = await value(sms, "document.body.innerText");
  sms.ws.close();
  return {
    code: [...text.matchAll(/c[oó]digo (\d{4})/gi)].at(-1)?.[1],
    link: [...text.matchAll(/https:\/\/mobileconnect\.telefonica\.es\/es\/sba\/c\/[^\s.]+/gi)].at(-1)?.[0],
  };
}

async function main() {
  mkdirSync(outDir, { recursive: true });

  const network = [];
  const page = await openPage(startURL);
  await page.send("Page.enable");
  await page.send("Runtime.enable");
  await page.send("Network.enable");

  page.on("Network.requestWillBeSent", (event) => network.push({ type: "request", ...event }));
  page.on("Network.responseReceived", (event) => network.push({ type: "response", ...event }));
  page.on("Network.loadingFailed", (event) => network.push({ type: "failed", ...event }));
  page.on("Network.loadingFinished", (event) => network.push({ type: "finished", ...event }));

  await sleep(3000);
  console.log("start page", await value(page, "document.body.innerText"));

  await value(
    page,
    `(() => {
      const phone = document.querySelector("#phoneNumberField");
      phone.value = "${phone}";
      phone.dispatchEvent(new Event("input", { bubbles: true }));
      document.querySelector("#rememberCheckbox").checked = true;
      document.querySelector("#mobileConnect\\\\.button").click();
      return true;
    })()`,
  );

  await sleep(8000);
  let text = await value(page, "document.body.innerText");
  console.log("after start", text.slice(0, 200));

  const sms = await latestSMS();
  console.log("sms", sms.code ? "code" : "no-code", sms.link ? "link" : "no-link");

  if (text.includes("Verifica tu identidad") && sms.code) {
    await value(
      page,
      `(() => {
        const code = "${sms.code}";
        [...document.querySelectorAll(".pin-inputs input[type=tel]")].forEach((input, i) => {
          input.value = code[i];
          input.dispatchEvent(new InputEvent("input", { bubbles: true }));
        });
        document.querySelector("#finish-button").disabled = false;
        document.querySelector("#finish-button").click();
        return true;
      })()`,
    );
  } else if (sms.link) {
    await page.send("Page.navigate", { url: sms.link });
    await sleep(4000);
    await value(page, `document.querySelector("#finish-button")?.click() ?? false`);
  }

  await sleep(12000);
  text = await value(page, "document.body.innerText");
  const location = await value(page, "location.href");
  const cookies = await page.send("Network.getCookies", { urls: ["https://cloud.o2online.es/"] });
  const fingerprint = await value(page, `localStorage.getItem("omhls.fingerprintKey")`);
  const root = await value(
    page,
    `(() => {
      const validationKey = document.cookie.match(/(?:^|; )validationKey=([^;]+)/)[1];
      return fetch("/sapi/media/folder/root?action=get&validationkey=" + validationKey, {
        headers: { "X-deviceid": "web-" + localStorage.getItem("omhls.fingerprintKey") }
      }).then(async (r) => ({ status: r.status, contentType: r.headers.get("content-type"), text: await r.text() }));
    })()`,
  );

  writeFileSync(new URL("browser-auth-network.json", outDir), JSON.stringify(network, null, 2));
  writeFileSync(
    new URL("browser-auth-result.json", outDir),
    JSON.stringify(
      {
        location,
        text: text.slice(0, 1000),
        cookieNames: cookies.cookies.map((cookie) => cookie.name),
        fingerprint,
        root,
      },
      null,
      2,
    ),
  );
  writeFileSync(
    new URL("session-private.json", outDir),
    JSON.stringify(
      {
        cookies: Object.fromEntries(
          cookies.cookies
            .filter((cookie) => ["validationKey", "JSESSIONID", "PLC"].includes(cookie.name))
            .map((cookie) => [cookie.name, cookie.value]),
        ),
        cookieMeta: cookies.cookies
          .filter((cookie) => ["validationKey", "JSESSIONID", "PLC"].includes(cookie.name))
          .map((cookie) => ({
            name: cookie.name,
            expires: cookie.expires,
            domain: cookie.domain,
            httpOnly: cookie.httpOnly,
          })),
        deviceId: "web-" + fingerprint,
      },
      null,
      2,
    ),
  );

  console.log("final", location);
  console.log("cookies", cookies.cookies.map((cookie) => cookie.name).join(", "));
  console.log("root", root.status, root.text.slice(0, 500));
  page.ws.close();
}

await main();
