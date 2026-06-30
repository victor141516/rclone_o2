# O2 Cloud Web API notes for rclone backend

This document is based on Chrome DevTools Protocol captures from the logged-in
O2 Cloud web app at `https://cloud.o2online.es/#folders`.

Raw captures are local and sensitive:

- Auth flow: `.cdp-captures/o2-auth/traffic-2026-06-29T23-48-19-579Z.jsonl`
- CRUD flow: `.cdp-captures/o2-crud/traffic-2026-06-29T23-58-12-487Z.jsonl`

Do not publish these captures. They contain cookies, validation keys, profile
data, download URLs, and phone/auth artifacts.

## rclone backend shape

Official rclone guidance says new backends usually live under
`backend/<name>/`, register themselves with `fs.Register`, expose `NewFs`, and
implement the core `fs.Fs` and `fs.Object` interfaces. Existing compact
backends such as `backend/fichier` and `backend/pixeldrain` are useful local
templates. For O2 Cloud the closest fit is:

- `backend/o2/o2.go`: `Fs`, `Object`, rclone interface methods, registration.
- `backend/o2/api/types.go`: JSON request/response structs.
- Use `fs/fshttp` with small JSON/form helpers for HTTP.
- Use `lib/dircache` because the O2 API addresses folders by numeric IDs.
- Register in `backend/all/all.go`.
- Add an integration-test shell similar to other backends after auth is stable.

## Hosts

- Web app/API: `https://cloud.o2online.es`
- Upload API: `https://upload.cloud.o2online.es`
- Mobile Connect identity provider: `https://mobileconnect.telefonica.es`

## Authentication

The web app uses Telefonica Mobile Connect with an OAuth/OIDC-style authorization
code flow, then exchanges the code with O2 Cloud.

Observed login sequence:

1. `POST /sapi/login/mobileconnect?action=start`
   - Content-Type: `application/x-www-form-urlencoded; charset=UTF-8`
   - Body: `platform=web&msisdn=<phone-number>`
   - Response: 200 with `data.authorizationurl`; the page navigates to that
     Telefonica URL.
2. Browser navigates to:
   - `https://mobileconnect.telefonica.es/es/oauth2/authorize`
   - Query includes `login_hint=MSISDN:<phone>`, `scope=openid phone`,
     `acr_values=2`, `response_type=code`, `redirect_uri=https://cloud.o2online.es/ui/html/mobileconnect.html`,
     `state`, `nonce`, `client_id=cb0db361-86cd-4d6d-921d-2256248c860b`.
3. Telefonica redirects through:
   - `/es/authrouter/authenticate?jwt=...`
   - `/es/sba/authenticate?jwt=...`
   - `/es/sba/polling?...` until user approval; returns 204 while pending.
   - `/es/sba/finish` via POST.
   - `/es/authrouter/authenticated?jwt=...`
   - `/es/oauth2/authorize/confirm?jwt=...`
4. Browser returns to:
   - `/ui/html/mobileconnect.html?code=<authorization-code>&state=<state>`
5. O2 Cloud session exchange:
   - `POST /sapi/login/mobileconnect?action=login`
   - Content-Type: `application/x-www-form-urlencoded; charset=UTF-8`
   - Body: `keytype=authorizationcode&state=<state>&key=<authorization-code>`
   - Response headers include `Set-Cookie: JSESSIONID=...` and
     `x-device-status: linked`.
   - Response body includes `data.validationkey`; the web app stores it as the
     `validationKey` cookie.

Post-login cookies observed via CDP:

- `validationKey`: JS-visible, `Secure`, path `/`, persistent.
- `JSESSIONID`: `HttpOnly`, `Secure`, domain `.cloud.o2online.es`, path `/`,
  persistent.

All API requests also include:

- `X-deviceid: web-<fingerprint>`; observed value format is a stable
  32-character hex fingerprint prefixed with `web-`.
- `Cookie` with `validationKey` and/or `JSESSIONID`.
- `validationkey=<validationKey>` query parameter.
- `withCredentials=true` in the browser.

The browser helper adds `validationkey` automatically to most `/sapi/...`
requests. If a request returns a `SEC-1003` validation error, the web bundle has
logic to update and retry the validation key.

The rclone backend supports one configuration path: manually import
`validation_key`, `jsessionid`, and `device_id` from an already logged-in browser
session.

The OTP/SMS approval happens in the browser/Telefonica page. rclone does not
submit the SMS code itself.

## Manual rclone configuration during development

The `rclone config` path imports values from an already logged-in browser:

1. Log in to `https://cloud.o2online.es/#folders` in Chrome/Helium.
2. Read the `validationKey` cookie, `JSESSIONID` cookie, and
   `localStorage["omhls.fingerprintKey"]` device id from that browser session.
   rclone accepts either the raw fingerprint value or the same value prefixed
   with `web-`.
3. Store them in an rclone remote:

```ini
[o2]
type = o2
validation_key = <obscured validationKey>
jsessionid = <obscured JSESSIONID>
device_id = web-<fingerprint>
```

Use `rclone obscure` for the two secret values when writing them to
`rclone.conf`. For temporary smoke tests, the same values can be supplied with
`RCLONE_CONFIG_<NAME>_VALIDATION_KEY`, `RCLONE_CONFIG_<NAME>_JSESSIONID`, and
`RCLONE_CONFIG_<NAME>_DEVICE_ID`.

After a remote has been configured, run the local smoke test from the repository
root to exercise quota, mkdir, upload, list, download, move, delete, and rmdir:

```console
backend/o2/smoke.sh o2:
```

Set `RCLONE=/path/to/rclone` or `O2_SMOKE_REMOTE=o2:path` if needed. The script
uses `-vv` so O2 backend debug logs are visible when something fails.

## Common headers

Requests usually include:

```text
Accept: */*
Content-Type: application/json;charset=UTF-8
X-deviceid: web-<fingerprint>
Origin: https://cloud.o2online.es
Referer: https://cloud.o2online.es/
Cookie: validationKey=...; JSESSIONID=...
```

Upload uses multipart and targets `upload.cloud.o2online.es`.

## Folder model

The root folder ID observed in this account is `27321630`. The web app has a
root-folder handler; for a backend, discover root using:

```http
GET /sapi/media/folder/root?action=get&validationkey=...
```

Observed response shape:

```json
{
  "data": {
    "folders": [
      {
        "name": "root-like-name",
        "id": 27321630,
        "status": "N",
        "magic": false,
        "offline": false,
        "parentid": 0,
        "date": 1782777624323
      }
    ]
  },
  "responsetime": 1782777624323
}
```

Some root responses may have a single folder object rather than a list; code
should tolerate both based on actual captures.

## List directory

A directory listing is a combination of folder list and media list.

Folders:

```http
GET /sapi/media/folder?action=list&parentid=<folder-id>&limit=200&validationkey=...
```

Response:

```json
{
  "data": {
    "folders": [
      {
        "name": "rclone-o2-test-1782777623",
        "id": 27321636,
        "status": "N",
        "magic": false,
        "offline": false,
        "parentid": 27321630,
        "date": 1782777624323
      }
    ]
  },
  "responsetime": 1782777624450
}
```

Files:

```http
POST /sapi/media?action=get&folderid=<folder-id>&limit=200&validationkey=...
Content-Type: application/json;charset=UTF-8

{
  "data": {
    "fields": [
      "name",
      "modificationdate",
      "size",
      "thumbnails",
      "videometadata",
      "audiometadata",
      "favorite",
      "shared",
      "etag"
    ]
  }
}
```

Response:

```json
{
  "data": {
    "media": [
      {
        "id": "1245088671",
        "date": 1782777753967,
        "mediatype": "file",
        "status": "U",
        "userid": "...",
        "modificationdate": 1782777749000,
        "size": 42,
        "name": "rclone-o2-upload-in-folder.txt",
        "etag": "m6Ia1XZIebRHZ8eny74soA==",
        "favorite": false,
        "shared": false
      }
    ],
    "more": false
  },
  "responsetime": 1782777759855
}
```

Notes:

- Timestamps appear to be milliseconds since Unix epoch.
- File IDs sometimes arrive as JSON strings.
- `more` indicates pagination may exist; only `limit=200` was observed.

## Create folder

```http
POST /sapi/media/folder?action=save&validationkey=...
Content-Type: application/json;charset=UTF-8

{
  "data": {
    "magic": false,
    "offline": false,
    "name": "<folder-name>",
    "parentid": <parent-folder-id>
  }
}
```

Response:

```json
{
  "data": {
    "folder": {
      "name": "rclone-o2-test-1782777623",
      "id": 27321636,
      "lastupdate": 1782777624323
    }
  },
  "success": "Folder saved successfully",
  "id": 27321636,
  "lastupdate": 1782777624323,
  "responsetime": 1782777624352
}
```

## Get folder metadata

```http
POST /sapi/media/folder?action=get&validationkey=...
Content-Type: application/json;charset=UTF-8

{"data":{"ids":[27321636]}}
```

Response:

```json
{
  "data": {
    "folders": [
      {
        "name": "rclone-o2-test-1782777623",
        "id": 27321636,
        "status": "N",
        "magic": false,
        "offline": false,
        "parentid": 27321630,
        "date": 1782777624323
      }
    ]
  },
  "responsetime": 1782777624403
}
```

## Upload file

```http
POST https://upload.cloud.o2online.es/sapi/upload?action=save&validationkey=...
Content-Type: multipart/form-data
X-deviceid: web-<fingerprint>
Cookie: ...
```

The browser constructs a `FormData` with two fields:

- `data`: JSON string.
- `file`: file blob.

Example `data` field:

```json
{
  "data": {
    "name": "rclone-o2-upload-formdata-probe.txt",
    "size": 16,
    "modificationdate": "",
    "contenttype": "text/plain",
    "folderid": 27321636
  }
}
```

Upload response:

```json
{
  "success": "Media uploaded successfully",
  "id": "1245091671",
  "status": "V",
  "etag": "X5nkwd8933dDYxRpM+JKfw==",
  "responsetime": 1782777809576,
  "type": "file"
}
```

The web app then polls validation and fetches metadata:

```http
POST /sapi/media?action=get-validation-status&validationkey=...
{"data":{"ids":[{"id":1245091671}]}}
```

Validation response:

```json
{"data":{"ids":[{"id":1245091671,"status":"U"}]}}
```

Then:

```http
POST /sapi/media?action=get&origin=omh,dropbox&validationkey=...
{
  "data": {
    "ids": [1245091671],
    "fields": [
      "creationdate",
      "postingdate",
      "name",
      "size",
      "thumbnails",
      "viewurl",
      "url",
      "videometadata",
      "audiometadata",
      "shared",
      "exported",
      "favorite",
      "origin",
      "folderid",
      "labels",
      "modificationdate",
      "uploadeddeviceid",
      "uploaded",
      "etag"
    ]
  }
}
```

Full metadata includes a signed download URL:

```json
{
  "id": "1245088671",
  "mediatype": "file",
  "status": "U",
  "url": "https://cloud.o2online.es/sapi/download/file?action=get&k=...&node=1i221",
  "creationdate": 1782777749000,
  "modificationdate": 1782777749000,
  "uploaded": 1782777749499,
  "size": 42,
  "name": "rclone-o2-upload-in-folder.txt",
  "etag": "m6Ia1XZIebRHZ8eny74soA==",
  "folder": 27321636,
  "favorite": false,
  "shared": false,
  "origin": {"name": "omh"},
  "uploadeddeviceid": "web-..."
}
```

## Download file

The UI first fetches full media metadata, then opens the signed `url` from the
metadata response. The actual download request observed:

```http
GET /sapi/download/file?action=get&k=<signed-key>&node=1i221&filename=<name>
```

For rclone:

1. Get metadata for the object ID using full fields.
2. Use the returned `url`.
3. Append `filename=<remote leaf>` if desired; the browser does.

Range support was not tested yet.

## Rename file / update file metadata

```http
POST /sapi/upload/file?action=save-metadata&validationkey=...
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

data={"data":{"id":1245091671,"name":"rclone-o2-renamed-probe.txt","folderid":27321636}}
```

The UI preserves extension separately in its dialog. For rclone, send the final
full filename.

## Delete file

The UI's delete operation moves to trash.

```http
POST /sapi/media/file?action=delete&softdelete=true&validationkey=...
Content-Type: application/json;charset=UTF-8

{"data":{"files":[1245091671]}}
```

Response body was captured as a normal 200 success. The UI then refreshes
storage, changes, softdeleted metadata, and the folder listing.

Hard delete from trash was not tested yet.

## Delete folder

The UI's folder delete operation moves to trash.

```http
POST /sapi/media/folder?action=softdelete&validationkey=...
Content-Type: application/json;charset=UTF-8

{"data":{"ids":[27321636]}}
```

The confirmation text says it deletes the folder and all content, but the
endpoint is `softdelete`.

Hard delete from trash was not tested yet.

## Remove file from folder

The context menu includes "Eliminar de la carpeta". The bundle defines:

```text
/sapi/media/folder?action=remove-item
```

This was not exercised because it is not the same as deleting an object from the
cloud; it likely detaches media from a folder while leaving it elsewhere.

## Move

The context menu includes "Trasladar a carpeta". The bundle defines:

```text
/sapi/media/folder?action=add-item
/sapi/media/folder?action=remove-item
```

The exact request payload for the UI's move dialog was not exercised yet. File
rename/update metadata accepts `folderid`, so the rclone backend currently uses
`/sapi/upload/file?action=save-metadata` with the same `id`, final `name`, and
destination `folderid` for file `Move`. Rename through this endpoint was
observed; cross-folder move through the same endpoint is an implementation
inference and should be verified against the live service before considering it
fully stable.

## Quota

```http
GET /sapi/media?action=get-storage-space&softdeleted=true&validationkey=...
```

Observed response:

```json
{
  "data": {
    "quota": 10995116277760,
    "softdeleted": 134,
    "free": 10995116277626,
    "used": 134,
    "nolimit": false,
    "individual": {
      "used": 134,
      "softdeleted": 134
    }
  },
  "responsetime": 1782778074731
}
```

Map to rclone `About` as:

- `Total`: `quota`, unless `nolimit` is true.
- `Used`: `used`.
- `Free`: `free`.
- `Trashed`: `softdeleted`.

## Error handling and retry

The web bundle treats HTTP 401 specially and has a validation-key retry path for
JSON errors with code `SEC-1003`. Backend should:

- Treat 401/403 as auth errors.
- Treat 404/not found API errors as rclone not found.
- Retry 429 and 5xx with `fs.Pacer`.
- Log method, endpoint, HTTP status, O2 error code, object/folder IDs, and
  operation names at debug level, without logging cookies, validation keys, or
  signed download keys.

## Backend implementation notes

Implemented backend shape:

- Config fields:
  - `validation_key` sensitive/password, stored obscured
  - `jsessionid` sensitive/password, stored obscured
  - `device_id` required, normalized to `web-<fingerprint>` if needed
  - `root_folder_id` advanced, default auto-discover
  - `api_url` advanced, default `https://cloud.o2online.es`
  - `upload_url` advanced, default `https://upload.cloud.o2online.es`
- On `Config`: standard rclone option prompts ask for manually imported browser
  session values.
- On `NewFs`:
  - Reveal obscured credentials.
  - Build HTTP client with cookies and default `X-deviceid`.
  - Discover root folder ID if absent.
  - Initialize `dircache`.
- Implement:
  - `FindLeaf`, `CreateDir` for `dircache`.
  - `List`: call folder list + media list.
  - `NewObject`: resolve parent with `dircache`, list files, match by name.
  - `Put`: multipart upload with `data` + `file`, then metadata fetch.
  - `Open`: fetch full metadata, open signed URL.
  - `Update`: upload replacement then delete old object if IDs differ.
  - `Remove`: softdelete file.
  - `Mkdir`: via `dircache.FindDir(..., true)`.
  - `Rmdir`: softdelete folder; may need empty check if rclone expects it.
  - `Purge`: softdelete a folder without requiring it to be empty.
  - `About`: map storage-space quota fields.
  - `Move`: file rename/move through `save-metadata`; cross-folder move is
    inferred and needs live verification.
  - Optional later: `DirMove`, trash restore/hard delete.
