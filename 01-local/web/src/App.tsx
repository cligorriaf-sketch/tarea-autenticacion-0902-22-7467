import { useState, type FormEvent } from "react";
import axios from "axios";
import api from "./api";

type Credentials = { username: string; password: string };
type TokenPair = { accessToken: string; refreshToken: string };

export default function App() {
  const [credentials, setCredentials] = useState<Credentials>({ username: "", password: "" });
  const [code, setCode] = useState("");
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [signedIn, setSignedIn] = useState(Boolean(localStorage.getItem("accessToken")));
  const [message, setMessage] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setMessage("");
    try {
      if (twoFactorRequired) {
        const { data } = await api.post<TokenPair>("/api/auth/2fa/verify", {
          ...credentials,
          code,
        });
        storeTokens(data);
        return;
      }

      const response = await api.post<TokenPair | { twoFactorRequired: boolean }>(
        "/api/auth/login",
        credentials,
      );
      if (response.status === 202) {
        setTwoFactorRequired(true);
        setMessage("Ingresa el código de tu aplicación TOTP.");
        return;
      }

      storeTokens(response.data as TokenPair);
    } catch {
      setMessage("No se pudo autenticar. Verifica los datos y vuelve a intentar.");
    }
  }

  function storeTokens(tokens: TokenPair) {
    localStorage.setItem("accessToken", tokens.accessToken);
    localStorage.setItem("refreshToken", tokens.refreshToken);
    setSignedIn(true);
    setTwoFactorRequired(false);
    setMessage("Sesión iniciada.");
  }

  async function logout() {
    let logoutMessage = "Sesión cerrada en este dispositivo.";
    try {
      const refreshToken = localStorage.getItem("refreshToken");
      if (refreshToken) {
        await api.post("/api/auth/logout", { refreshToken });
      }
    } catch (error) {
      logoutMessage = axios.isAxiosError(error)
        ? "Se limpió la sesión local, pero no se pudo revocar el refresh token en el servidor."
        : "Se limpió la sesión local, pero ocurrió un error inesperado al revocar el token.";
    } finally {
      localStorage.removeItem("accessToken");
      localStorage.removeItem("refreshToken");
      setSignedIn(false);
      setMessage(logoutMessage);
    }
  }

  return (
    <main>
      <h1>Autenticación local</h1>
      {signedIn ? (
        <section>
          <p>Sesión activa. Las solicitudes protegidas renuevan el access token una sola vez.</p>
          <button onClick={logout}>Cerrar sesión</button>
        </section>
      ) : (
        <form onSubmit={submit}>
          <label>
            Usuario
            <input
              autoComplete="username"
              value={credentials.username}
              onChange={(event) => setCredentials({ ...credentials, username: event.target.value })}
              required
            />
          </label>
          <label>
            Contraseña
            <input
              type="password"
              autoComplete="current-password"
              value={credentials.password}
              onChange={(event) => setCredentials({ ...credentials, password: event.target.value })}
              required
            />
          </label>
          {twoFactorRequired && (
            <label>
              Código TOTP
              <input
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                required
              />
            </label>
          )}
          <button type="submit">{twoFactorRequired ? "Verificar código" : "Iniciar sesión"}</button>
        </form>
      )}
      {message && <p role="status">{message}</p>}
    </main>
  );
}
