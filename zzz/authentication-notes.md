# Entorno de pruebas de autenticacion O2 Cloud

Este directorio `zzz` se usara como laboratorio en Node para investigar la autenticacion de O2 Cloud sin tocar todavia el backend en Go de rclone ni ensuciar el resto del proyecto.

## Contexto

El backend actual puede autenticarse si el usuario copia desde el navegador la cookie `validationKey`, la cookie `JSESSIONID` y el valor de local storage `omhls.fingerprintKey`. Eso funciona, pero la sesion web caduca bastante rapido, asi que no es una solucion suficientemente robusta.

La web es el flujo mas facil de inspeccionar, pero O2 Cloud tambien tiene app movil y app de escritorio. Es posible que esas apps usen sesiones, tokens o renovaciones con una caducidad mas larga. Aun asi, el primer objetivo de este entorno no es investigar movil/escritorio, sino reproducir el flujo SMS observado en web.

## Objetivo inicial

Replicar desde Node el flujo de autenticacion por SMS:

1. Iniciar el login de Mobile Connect / SMS contra los endpoints de O2 Cloud.
2. Pedir o recibir el codigo SMS introducido por el usuario.
3. Completar el intercambio hasta obtener una sesion utilizable.
4. Identificar exactamente que credenciales finales hacen falta para llamar al API de storage.
5. Documentar tiempos de caducidad, cookies, cabeceras y cualquier token renovable.

## Estado actual

Hay tres scripts utiles:

- `browser-auth-har.mjs`: automatiza el flujo en una pestana real de Chrome via
  CDP, lee el SMS desde la pestana de httpSMS, guarda una traza de red en
  `out/browser-auth-network.json` y guarda el resultado en
  `out/browser-auth-result.json`.
- `renew-without-sms.mjs`: prueba la renovacion sin SMS usando
  `validationKey + PLC`, simula la ausencia de `JSESSIONID`, aplica el retry de
  `SEC-1003` y lista la raiz.
- `index.ts`: version Node/Bun minima del flujo HTTP, con headers completos de
  navegador, cookie jar propia, lectura simple del SMS por CDP, canje final de
  `code/state` y listado de la raiz. Parte de las cookies actuales copiadas del
  navegador, igual que las requests originales.

```bash
node browser-auth-har.mjs
node renew-without-sms.mjs
bun run index.ts
```

No ejecutar muchos intentos seguidos. El proveedor devuelve `phone_blocked`
despues de varios intentos de autenticacion en poco tiempo, lo que puede
confundirse facilmente con que falta algun header.

## Flujo observado

### 1. Inicio en O2 Cloud

Request:

```http
POST https://cloud.o2online.es/sapi/login/mobileconnect?action=start&validationkey=<validationKey si existe>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-deviceid: web-<omhls.fingerprintKey>

platform=web&msisdn=<telefono>&rememberme=true
```

Resultado:

- Devuelve JSON con `data.authorizationurl`.
- `rememberme=true` es importante: despues del login final aparece la cookie
  persistente `PLC`, que permite renovar sin SMS.

### 2. Navegacion a Mobile Connect

La `authorizationurl` apunta a:

```text
https://mobileconnect.telefonica.es/es/oauth2/authorize?... 
```

Con el perfil `full`, el flujo llega al formulario SMS. La traza manual
observada es:

```text
/es/oauth2/authorize
  -> /es/authrouter/authenticate?jwt=...
  -> /es/sba/authenticate?jwt=...
  -> 200 HTML "Validacion Movil"
```

Cookies observadas:

- `connect.sid` en `mobileconnect.telefonica.es`.
- `xbacsrftoken` al servir la pagina SMS.

El formulario final:

- Se sirve desde `mobileconnect.telefonica.es/es/sba/authenticate?jwt=...`.
- Tiene `action="/es/sba/finish"` y `method="post"`.
- Incluye hidden inputs `csrfmiddlewaretoken`, `corr`, `nonce`, `trans` y
  `code`.
- El JavaScript configura `X-CSRFToken` para requests no seguras.
- Los endpoints auxiliares son `/es/sba/resend` y `/es/sba/polling`.

Tambien funciona la alternativa del enlace SMS:

```text
https://mobileconnect.telefonica.es/es/sba/c/<codigo-link>
  -> HTML "Cloud - Permites acceder a la aplicacion?"
  -> POST /es/sba/c/confirm con action=finish
```

### 3. Callback a O2 Cloud

Tras completar el codigo o confirmar el enlace SMS, Mobile Connect redirige a:

```text
https://cloud.o2online.es/ui/html/mobileconnect.html?code=<authorization-code>&state=<state>
```

La web canjea ese `code` con:

```http
POST https://cloud.o2online.es/sapi/login/mobileconnect?action=login&validationkey=<old-validationKey>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-deviceid: web-<omhls.fingerprintKey>

keytype=authorizationcode&state=<state>&key=<authorization-code>
```

Cookies finales observadas con `rememberme=true`:

- `validationKey`: expira en unos 15 dias.
- `JSESSIONID`: expira en torno a 1 dia.
- `PLC`: expira en torno a 90 dias.

### 4. Listado de storage

Los endpoints `/sapi/...` necesitan:

- Cookie `validationKey`.
- Cookie `JSESSIONID`.
- Query param `validationkey=<validationKey>`.
- Header `X-deviceid: web-<omhls.fingerprintKey>`.

Listado verificado:

```http
GET https://cloud.o2online.es/sapi/media/folder/root?action=get&validationkey=<validationKey>
X-deviceid: web-<omhls.fingerprintKey>
Cookie: validationKey=<...>; JSESSIONID=<...>
```

Resultado verificado: `200` con la carpeta raiz `/`.

### 5. Renovacion sin SMS

Mecanismo observado y verificado:

1. Si falta o ha caducado `JSESSIONID`, se puede llamar al API con
   `validationKey + PLC`, sin SMS.
2. La primera llamada devuelve `401` con `SEC-1003`, incluye una nueva
   `validationKey` en `error.data` y ademas setea cookies nuevas
   `JSESSIONID` y `PLC`.
3. Actualizando la cookie `validationKey` con `error.data`, guardando los
   `Set-Cookie` recibidos y reintentando la misma request, el listado responde
   `200`.

Esto hace que el SMS solo sea necesario para la primera autenticacion mientras
la cookie persistente `PLC` siga viva. En la prueba actual, `PLC` tenia una
caducidad aproximada de 90 dias.

### 6. Velocidad de subida

Captura real desde Chrome, confirmando el modal de subida:

- `POST https://upload.cloud.o2online.es/sapi/upload?action=save&acceptasynchronous=true&validationkey=<validationKey>`
- Protocolo: HTTP/2 (`h2`).
- `Content-Length` conocido: `1322815538` bytes para `caminito.m4a`.
- Duracion observada en Chrome: ~36 s, unos 35 MiB/s.
- Cookies enviadas por Chrome en el `POST`: solo `JSESSIONID`.
- `validationKey` va en query param, no hace falta mandarla tambien como cookie
  en upload.
- `PLC` no se envia en el `POST` de upload.

Pruebas comparativas:

- rclone con la sesion antigua de `/tmp/rclone-o2-browser.conf`: ~4 MiB/s.
- `curl` con la sesion exacta de Chrome y el mismo nodo del ELB: ~39.6 MB/s.
- rclone con la sesion exacta de Chrome en la misma config temporal: ~37.9
  MiB/s.

Conclusion: el cuello no estaba en Go, HTTP/2, `Content-Length` ni la forma del
multipart, sino en la sesion concreta guardada en la config. Actualizar
`validation_key`, `jsessionid`, `plc` y `device_id` con los valores de la sesion
rapida de Chrome hace que el mismo comando de rclone suba a velocidad de web.

Matiz observado el 2026-07-05: la misma sesion de Chrome y el mismo nodo del ELB
tambien dieron el camino lento (~5 MiB/s) tanto con rclone como con `curl`. Eso
descarta una regresion del cliente en esa prueba y sugiere que la velocidad
puede depender de estado temporal de sesion/backend, no solo de la forma exacta
de la request.

Pruebas genericas del 2026-07-05:

- Se elimino la logica especifica para `.m4a`. El upload usa el MIME detectado
  por rclone para la parte `file`, o `application/octet-stream` si no se conoce.
- La metadata de upload es la misma para cualquier extension: no se envia
  `contenttype` en el JSON `data`.
- Subidas con datos aleatorios de 32 MiB y extensiones `.m4a`, `.txt`, `.exe` y
  `.zxq` completaron correctamente.
- Una subida desde el propio Chrome con `fetch` + `FormData`, Blob aleatorio de
  16 MiB y extension inventada `.zxq`, tambien fue lenta (~2.17 MiB/s). Por
  tanto, en esa medicion la lentitud no era especifica de rclone ni de la
  extension.

## Errores vistos al reducir headers

Estos resultados todavia no son concluyentes porque habia autenticaciones SMS
pendientes y despues salto el rate limit:

- `lean` termino redirigiendo a `mobileconnect.html?error=access_denied` con
  `error_description=authenticating_in_progress`.
- Intentos posteriores en paralelo terminaron en `error_description=phone_blocked`.

Por tanto, no se puede afirmar todavia que `lean` falle por falta de headers.
La siguiente ronda debe hacerse de una en una, esperando a que caduque o se
complete el intento anterior.

## Hipotesis sobre cabeceras

Comprobado:

- El flujo con headers completos clonados del navegador llega al formulario SMS.

Por comprobar:

- Si el GET a `authorizationurl` necesita realmente `sec-fetch-*`.
- Si necesita Client Hints (`sec-ch-ua`, `sec-ch-ua-mobile`,
  `sec-ch-ua-platform`).
- Si `Referer: https://cloud.o2online.es/` es obligatorio.
- Si `upgrade-insecure-requests: 1` afecta al resultado.

## Notas sobre NodeSession

Para investigar redirects y cookies intermedias ha resultado mas fiable usar
`fetch` con redirects manuales o CDP del navegador. `NodeSession` puede servir
para experimentos simples, pero oculta redirects seguidos internamente por
`node-fetch`.

## Criterio de exito

El experimento sera util si un script de Node puede crear una sesion nueva partiendo de cero, sin depender de cookies copiadas manualmente de DevTools, y despues llamar a endpoints basicos del storage como listar carpetas o listar archivos.

## Restricciones

- Mantener toda la experimentacion dentro de `zzz`.
- No portar nada al backend Go hasta entender bien el flujo.
- No registrar codigos SMS, cookies, tokens ni datos personales en logs persistentes.
- Si se capturan respuestas HTTP para depurar, guardarlas redacted o fuera del repo.

## Siguientes lineas de investigacion

Primero se intentara reproducir el login SMS de la web. Si ese flujo resulta inestable, demasiado atado al navegador o con caducidad corta, se estudiaran despues la app movil y la app de escritorio como posibles fuentes de un modelo de sesion mas duradero.
