import { useCallback, useEffect, useState } from "react";
import { useAuth0 } from "@auth0/auth0-react";
import { jwtDecode } from "jwt-decode";

type Message = { id: number; text: string; createdBy: string };
type AccessTokenClaims = { permissions?: string[] };

const apiUrl = import.meta.env.VITE_API_URL ?? "http://localhost:5001";

export default function App() {
  const { isAuthenticated, isLoading, loginWithRedirect, logout, getAccessTokenSilently } = useAuth0();
  const [messages, setMessages] = useState<Message[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [error, setError] = useState("");

  const loadMessages = useCallback(async () => {
    try {
      setError("");
      const accessToken = await getAccessTokenSilently();
      if (!accessToken) {
        throw new Error("Auth0 no devolvió un access token para la API.");
      }

      const claims = jwtDecode<AccessTokenClaims>(accessToken);
      setPermissions(claims.permissions ?? []);
      const response = await fetch(`${apiUrl}/api/messages`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        throw new Error(`La API respondió HTTP ${response.status}.`);
      }

      setMessages((await response.json()) as Message[]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "No se pudieron cargar los mensajes.");
    }
  }, [getAccessTokenSilently]);

  useEffect(() => {
    if (isAuthenticated) {
      void loadMessages();
    }
  }, [isAuthenticated, loadMessages]);

  async function deleteMessage(id: number) {
    try {
      const accessToken = await getAccessTokenSilently();
      const response = await fetch(`${apiUrl}/api/messages/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        throw new Error(`No se pudo eliminar: HTTP ${response.status}.`);
      }
      setMessages((current) => current.filter((message) => message.id !== id));
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "No se pudo eliminar el mensaje.");
    }
  }

  if (isLoading) return <main><p>Cargando sesión...</p></main>;
  if (!isAuthenticated) {
    return <main><h1>Mensajes</h1><button onClick={() => void loginWithRedirect()}>Iniciar sesión</button></main>;
  }

  return (
    <main>
      <header>
        <h1>Mensajes</h1>
        <button onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })}>
          Cerrar sesión
        </button>
      </header>
      {error && <p role="alert">{error}</p>}
      <p>Permisos del access token: {permissions.join(", ") || "ninguno"}</p>
      <ul>
        {messages.map((message) => (
          <li key={message.id}>
            <span>{message.text} <small>(creado por {message.createdBy})</small></span>
            {permissions.includes("delete:messages") && (
              <button onClick={() => void deleteMessage(message.id)}>Eliminar</button>
            )}
          </li>
        ))}
      </ul>
    </main>
  );
}
