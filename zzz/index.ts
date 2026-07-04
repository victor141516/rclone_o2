// @ts-nocheck

const phone = "34636025908";
const cdp = "http://127.0.0.1:19999";
const deviceId = "web-7768c7fc83d8c7e1e778567d5c58cf58";
const cookies = [
  { name: "validationKey", value: "5c383238764e502b332220555d4e3c29", domain: "cloud.o2online.es" },
  { name: "JSESSIONID", value: "C813090696D5855CCFF4BD4F35AF7C5C.2i46", domain: "cloud.o2online.es" },
  {
    name: "PLC",
    value: "4a3eaff57f3bc741657e796a149126557fe4a78f|609d35f3de37826113f1f55b2ad765318fe51895|6ec43dd5d27c0405f31b5793444f8ba2a68351e9",
    domain: "cloud.o2online.es",
  },
];

const browserHeaders = {
  "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"macOS"',
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
};

const htmlHeaders = {
  accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  ...browserHeaders,
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-user": "?1",
  "upgrade-insecure-requests": "1",
};

const xhrHeaders = {
  accept: "*/*",
  ...browserHeaders,
  "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
  priority: "u=1, i",
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "same-origin",
  "x-deviceid": deviceId,
  referer: "https://cloud.o2online.es/",
};

function remember(response, url) {
  const host = new URL(url).hostname;
  for (const raw of response.headers.getSetCookie()) {
    const parts = raw.split(";").map((part) => part.trim());
    const eq = parts[0].indexOf("=");
    const cookie = {
      name: parts[0].slice(0, eq),
      value: parts[0].slice(eq + 1),
      domain: (parts.find((part) => part.toLowerCase().startsWith("domain="))?.split("=")[1] ?? host).replace(/^\./, ""),
    };
    const index = cookies.findIndex((item) => item.name === cookie.name && item.domain === cookie.domain);
    index === -1 ? cookies.push(cookie) : (cookies[index] = cookie);
  }
}

function cookieHeader(url) {
  const host = new URL(url).hostname;
  return cookies
    .filter((cookie) => host === cookie.domain || host.endsWith(`.${cookie.domain}`))
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

function cookieValue(name) {
  return cookies.find((cookie) => cookie.name === name)?.value;
}

function setCookieValue(name, value, domain = "cloud.o2online.es") {
  const index = cookies.findIndex((cookie) => cookie.name === name && cookie.domain === domain);
  index === -1 ? cookies.push({ name, value, domain }) : (cookies[index].value = value);
}

function loginURL(action) {
  return `https://cloud.o2online.es/sapi/login/mobileconnect?action=${action}&validationkey=${cookieValue("validationKey")}`;
}

async function request(url, init = {}) {
  for (;;) {
    const headers = { ...(init.headers ?? {}) };
    const cookie = cookieHeader(url);
    if (cookie) headers.cookie = cookie;

    const response = await fetch(url, { ...init, headers, redirect: "manual" });
    remember(response, url);

    if (response.status < 300 || response.status >= 400) return { response, url };
    url = new URL(response.headers.get("location"), url).href;
    init = { method: "GET", headers: init.headers };
  }
}

function hiddenInputs(html) {
  return Object.fromEntries(
    [...html.matchAll(/<input\b[^>]*type=["']hidden["'][^>]*>/gi)].map(([input]) => [
      input.match(/\bname=["']([^"']+)["']/i)?.[1],
      input.match(/\bvalue=["']([^"']*)["']/i)?.[1] ?? "",
    ]),
  );
}

async function latestSMS() {
  const pages = await fetch(`${cdp}/json/list`).then((r) => r.json());
  const page = pages.find((p) => p.title.includes("httpSMS"));
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (pending.has(msg.id)) pending.get(msg.id)(msg.result);
  };
  await new Promise((resolve) => (ws.onopen = resolve));
  const send = (method, params = {}) => {
    ws.send(JSON.stringify({ id: ++id, method, params }));
    return new Promise((resolve) => pending.set(id, resolve));
  };
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Page.reload", { ignoreCache: true });
  await new Promise((resolve) => setTimeout(resolve, 5000));
  const text = (await send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true })).result.value;
  ws.close();
  return {
    code: [...text.matchAll(/c[oó]digo (\d{4})/gi)].at(-1)?.[1],
    link: [...text.matchAll(/https:\/\/mobileconnect\.telefonica\.es\/es\/sba\/c\/[^\s.]+/gi)].at(-1)?.[0],
  };
}

async function listRoot() {
  return await request(`https://cloud.o2online.es/sapi/media/folder/root?action=get&validationkey=${cookieValue("validationKey")}`, {
    headers: {
      accept: "*/*",
      referer: "https://cloud.o2online.es/",
      "x-deviceid": deviceId,
    },
  });
}

const start = await request(loginURL("start"), {
  method: "POST",
  headers: xhrHeaders,
  body: new URLSearchParams({ platform: "web", msisdn: phone, rememberme: "true" }),
});
const { data } = await start.response.json();
console.log("start", start.response.status);

const smsPage = await request(data.authorizationurl, {
  headers: {
    ...htmlHeaders,
    referer: "https://cloud.o2online.es/",
    "sec-fetch-site": "cross-site",
  },
});
const smsHTML = await smsPage.response.text();
await new Promise((resolve) => setTimeout(resolve, 10000));
const sms = await latestSMS();
console.log("sms", sms.code ? "code" : "link");

let finish;
if (smsPage.url.includes("mobileconnect.telefonica.es")) {
  const fields = hiddenInputs(smsHTML);
  finish = await request(new URL("/es/sba/finish", smsPage.url).href, {
    method: "POST",
    headers: {
      ...htmlHeaders,
      "content-type": "application/x-www-form-urlencoded",
      origin: new URL(smsPage.url).origin,
      referer: smsPage.url,
      "sec-fetch-site": "same-origin",
      "x-csrftoken": fields.csrfmiddlewaretoken,
    },
    body: new URLSearchParams({ ...fields, code: sms.code, action: "finish" }),
  });
} else {
  const confirmPage = await request(sms.link, { headers: htmlHeaders });
  const fields = hiddenInputs(await confirmPage.response.text());
  finish = await request(new URL("/es/sba/c/confirm", confirmPage.url).href, {
    method: "POST",
    headers: {
      ...htmlHeaders,
      "content-type": "application/x-www-form-urlencoded",
      origin: new URL(confirmPage.url).origin,
      referer: confirmPage.url,
      "sec-fetch-site": "same-origin",
      "x-csrftoken": fields.csrfmiddlewaretoken,
    },
    body: new URLSearchParams({ ...fields, action: "finish" }),
  });
}
console.log("finish", finish.response.status, finish.url);

const callback = new URL(finish.url);
const login = await request(loginURL("login"), {
  method: "POST",
  headers: xhrHeaders,
  body: new URLSearchParams({
    keytype: "authorizationcode",
    state: callback.searchParams.get("state"),
    key: callback.searchParams.get("code"),
  }),
});
console.log("login", login.response.status, cookies.map((cookie) => cookie.name).join(", "));

let root = await listRoot();
let rootText = await root.response.text();
if (root.response.status === 401) {
  const nextValidationKey = JSON.parse(rootText).error?.data;
  setCookieValue("validationKey", nextValidationKey);
  root = await listRoot();
  rootText = await root.response.text();
}
console.log("root", root.response.status, rootText);
