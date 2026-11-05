# Entrega: Autenticación, RBAC y MFA

Proyecto académico en dos partes: autenticación local con refresh tokens rotativos y una API de mensajes protegida por Auth0 RBAC. El informe exportable se encuentra en [`ENTREGA.md`](./ENTREGA.md).

## Requisitos

- .NET SDK 10.0.
- Node.js 20 o posterior y npm.
- El tenant Auth0 de laboratorio configurado para `02-auth0` o un tenant propio con los mismos permisos.
- Para compilar frontends: conexión a npm registry.

No se incluyen secretos ni claves privadas en el repositorio. Los archivos `.env.example` contienen solo nombres y ejemplos públicos; cópielos a `.env` y complete valores locales. En la API local se usa .NET User Secrets.

## 1. Proyecto `01-local`

### Configurar secretos de desarrollo

Desde PowerShell, en la raíz. El comando de clave de firma crea un valor aleatorio nuevo en el almacén local de User Secrets:

```powershell
dotnet user-secrets set "Jwt:SigningKey" ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))) --project .\01-local\api\LocalAuth.Api.csproj
dotnet user-secrets set "Demo:Username" "demo" --project .\01-local\api\LocalAuth.Api.csproj
.\01-local\api\scripts\Set-DemoPassword.ps1
```

El script solicita la contraseña de forma oculta y guarda solamente un hash PBKDF2-SHA256 con sal aleatoria en User Secrets. La cuenta y la contraseña de demostración no se versionan. TOTP es opcional; al configurarlo, `/api/auth/login` solicita un segundo factor y `/api/auth/2fa/verify` verifica el código:

```powershell
$totpSecret = python -c "import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip('='))"
dotnet user-secrets set "Demo:TotpSecret" $totpSecret --project .\01-local\api\LocalAuth.Api.csproj
Remove-Variable totpSecret
```

Agregue el secreto generado a una aplicación TOTP por el procedimiento de alta aprobado para su entorno de laboratorio; no lo publique ni lo suba al repositorio. Si se deja vacío, el login de demostración emite el par de tokens al validar la contraseña.

### Ejecutar

Terminal 1 (API):

```powershell
dotnet run --project .\01-local\api\LocalAuth.Api.csproj -- --urls http://localhost:5000
```

Terminal 2 (web):

```powershell
Copy-Item .\01-local\web\.env.example .\01-local\web\.env
Set-Location .\01-local\web
npm install
npm run dev
```

Abra `http://localhost:5173`. SQLite crea `local-auth.db` en el directorio de trabajo desde el que se inicia la API. Use las solicitudes reproducibles de [`01-local/requests.http`](./01-local/requests.http); el archivo de consulta [`01-local/refresh-tokens.sql`](./01-local/refresh-tokens.sql) permite inspeccionar que solo se almacenan hashes. Ejecute la prueba de reutilización y la prueba de seis logins en ventanas distintas: espere más de un minuto entre ellas para que no compartan el límite por IP. Para probar login con TOTP, envíe `username` y `password` a `/api/auth/login`, y luego las mismas credenciales más `code` de seis dígitos a `/api/auth/2fa/verify`.

El arranque crea la tabla de estado anti-replay de TOTP si todavía no existe, también en una base SQLite de laboratorio creada antes de agregar esa protección. El último paso aceptado por usuario se conserva para rechazar la repetición del mismo código.

Endpoints clave:

- `POST /api/auth/login`
- `POST /api/auth/2fa/verify`
- `POST /api/auth/refresh` con `{ "refreshToken": "..." }`
- `POST /api/auth/logout` con `{ "refreshToken": "..." }`
- `GET /api/health`

El limitador de login y 2FA es fijo, por IP, cinco peticiones por minuto, sin cola; el exceso recibe `429`.

## 2. Proyecto `02-auth0`

Siga la guía detallada de Auth0 en [`ENTREGA.md`](./ENTREGA.md#parte-2-roles-y-permisos-con-auth0). Configure los valores de la API con User Secrets:

```powershell
dotnet user-secrets set "Auth0:Domain" "dev-zr6osvtupoixpvyn.us.auth0.com" --project .\02-auth0\api\Auth0Messages.Api.csproj
dotnet user-secrets set "Auth0:Audience" "https://university-notes-api" --project .\02-auth0\api\Auth0Messages.Api.csproj
```

Terminal 1 (API):

```powershell
dotnet run --project .\02-auth0\api\Auth0Messages.Api.csproj -- --urls http://localhost:5001
```

Terminal 2 (web), después de completar `.env` a partir de `.env.example` con Domain, Client ID público y Audience:

```powershell
Copy-Item .\02-auth0\web\.env.example .\02-auth0\web\.env
Set-Location .\02-auth0\web
npm install
npm run dev
```

El `.env.example` contiene el Domain, Client ID público, Audience y URL local de la API configurados. Copie ese ejemplo a `.env` y no agregue Client Secret ni tokens. La SPA ya tiene `http://localhost:5174` en Allowed Callback URLs, Allowed Logout URLs y Allowed Web Origins. La API solo acepta JWT emitidos por el tenant configurado y destinados a la audiencia configurada.

La demostración usa el tenant nuevo `dev-zr6osvtupoixpvyn.us.auth0.com` (no es el tenant de clase), la API `University Notes API` y la audiencia `https://university-notes-api`. Allí se configuraron RBAC, los permisos `read:messages` y `delete:messages`, y los roles Lector/Administrador. Las capturas de configuración y pruebas reales `403`/`200` se encuentran en [`02-auth0/evidence`](./02-auth0/evidence). Se usaron dos usuarios de prueba; sus contraseñas no se incluyen en el repositorio ni en este README. El Dashboard mostró una notificación de prueba temporal; no se proporcionó información de pago.

Pruebe las autorizaciones con [`02-auth0/requests.http`](./02-auth0/requests.http). Mantenga los access tokens de prueba en variables privadas del cliente HTTP, nunca en el archivo versionado.

## Seguridad y alcance

- Este es un laboratorio reproducible, no un sistema listo para producción. La identidad local se configura como una cuenta de demostración; integre un proveedor de identidad/ASP.NET Core Identity para altas, gestión de credenciales, bloqueo por cuenta y ciclo de vida de MFA real.
- El cliente local guarda tokens en `localStorage` para mostrar el flujo solicitado. Cualquier XSS puede leerlos. En una aplicación real, prefiera refresh tokens en cookies `HttpOnly`, `Secure`, `SameSite` con protección CSRF, o use un BFF.
- En producción agregue también limitación por cuenta/usuario y controles de concurrencia/telemetría distribuidos, haga proxy forwarding solo desde proxies confiables, gestione claves en un vault y habilite HTTPS.
- El ejemplo usa `EnsureCreated` para SQLite de laboratorio y un almacén concurrente en memoria para mensajes; la lista de mensajes se reinicia al reiniciar la API.
- La dependencia `SQLitePCLRaw.bundle_e_sqlite3` se fija en `2.1.14` para no resolver la versión vulnerable `2.1.11` detectada durante la auditoría de paquetes.

## Documento de entrega

El documento Word [`Tarea-Autenticacion-0902-22-7467.docx`](./Tarea-Autenticacion-0902-22-7467.docx) contiene portada con el curso Desarrollo web, fragmentos, justificaciones, ensayo Passkeys vs. TOTP, referencias APA 7 y capturas locales y Auth0. El código y los documentos ya están publicados en el [repositorio público de GitHub](https://github.com/cligorriaf-sketch/tarea-autenticacion-0902-22-7467).

Antes de agregar nuevos archivos o hacer otro push, verifica que `.env` reales, tokens, contraseñas y secretos no estén incluidos; el `.gitignore` excluye los archivos de entorno locales y solo se publica `.env.example`. La consigna original solicita cargar un PDF a Canvas; si se mantiene ese requisito, exporta el DOCX final como `Tarea-Autenticacion-0902-22-7467.pdf`.
