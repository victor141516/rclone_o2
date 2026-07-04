import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const cdp = "http://127.0.0.1:19999";
const sessionFile = new URL("./out/session-private.json", import.meta.url);

class CDP {
  constructor(wsURL) {
    this.ws = new WebSocket(wsURL);
    this.id = 0;
    this.pending = new Map();
    this.ready = new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (!this.pending.has(msg.id)) return;
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
    };
  }

  async send(method, params = {}) {
    await this.ready;
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => reject(new Error(`Timeout ${method}`)), 15000);
    });
  }
}

async function sessionFromBrowser() {
  const pages = await fetch(`${cdp}/json/list`).then((r) => r.json());
  const tab = pages.find((page) => page.url.includes("cloud.o2online.es/#"));
  const page = new CDP(tab.webSocketDebuggerUrl);
  await page.send("Runtime.enable");
  await page.send("Network.enable");
  const cookies = await page.send("Network.getCookies", { urls: ["https://cloud.o2online.es/"] });
  const fingerprint = await page.send("Runtime.evaluate", {
    expression: `localStorage.getItem("omhls.fingerprintKey")`,
    returnByValue: true,
  });
  page.ws.close();
  return {
    cookies: Object.fromEntries(
      cookies.cookies
        .filter((cookie) => ["validationKey", "JSESSIONID", "PLC"].includes(cookie.name))
        .map((cookie) => [cookie.name, cookie.value]),
    ),
    deviceId: "web-" + fingerprint.result.value,
  };
}

function cookieHeader(cookies) {
  return Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

function applySetCookie(cookies, response) {
  for (const raw of response.headers.getSetCookie()) {
    const first = raw.split(";")[0];
    const eq = first.indexOf("=");
    cookies[first.slice(0, eq)] = first.slice(eq + 1);
  }
}

async function listRoot(session) {
  const url =
    "https://cloud.o2online.es/sapi/media/folder/root?action=get&validationkey=" +
    encodeURIComponent(session.cookies.validationKey);
  const response = await fetch(url, {
    headers: {
      cookie: cookieHeader(session.cookies),
      referer: "https://cloud.o2online.es/",
      "X-deviceid": session.deviceId,
    },
  });
  applySetCookie(session.cookies, response);
  return { status: response.status, text: await response.text() };
}

mkdirSync(new URL("./out/", import.meta.url), { recursive: true });

const session = existsSync(sessionFile)
  ? JSON.parse(readFileSync(sessionFile, "utf8"))
  : await sessionFromBrowser();

delete session.cookies.JSESSIONID;

let result = await listRoot(session);
if (result.status === 401) {
  const nextValidationKey = JSON.parse(result.text).error?.data;
  if (nextValidationKey) {
    session.cookies.validationKey = nextValidationKey;
    result = await listRoot(session);
  }
}

writeFileSync(sessionFile, JSON.stringify(session, null, 2));
console.log("renewed", result.status, Object.keys(session.cookies).join(", "));
console.log(result.text);
