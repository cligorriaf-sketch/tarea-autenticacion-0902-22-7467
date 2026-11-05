import axios, { type InternalAxiosRequestConfig } from "axios";

declare module "axios" {
  export interface InternalAxiosRequestConfig {
    retryCount?: number;
  }
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:5000",
});

let refreshInProgress: Promise<string> | null = null;

api.interceptors.request.use((config) => {
  const accessToken = localStorage.getItem("accessToken");
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error: unknown) => {
    if (!axios.isAxiosError(error) || !error.config || error.response?.status !== 401) {
      return Promise.reject(error);
    }

    const original = error.config as InternalAxiosRequestConfig;
    if (
      original.retryCount === 1 ||
      original.url?.startsWith("/api/auth/")
    ) {
      return Promise.reject(error);
    }

    original.retryCount = 1;
    try {
      if (!localStorage.getItem("refreshToken")) {
        throw new Error("No hay refresh token para renovar la sesión.");
      }

      refreshInProgress ??= axios
        .post<{ accessToken: string; refreshToken: string }>(
          `${api.defaults.baseURL}/api/auth/refresh`,
          { refreshToken: localStorage.getItem("refreshToken") },
        )
        .then(({ data }) => {
          localStorage.setItem("accessToken", data.accessToken);
          localStorage.setItem("refreshToken", data.refreshToken);
          return data.accessToken;
        })
        .finally(() => {
          refreshInProgress = null;
        });

      const accessToken = await refreshInProgress;
      original.headers.Authorization = `Bearer ${accessToken}`;
      return api(original);
    } catch (refreshError) {
      localStorage.removeItem("accessToken");
      localStorage.removeItem("refreshToken");
      window.location.assign("/");
      return Promise.reject(refreshError);
    }
  },
);

export default api;
