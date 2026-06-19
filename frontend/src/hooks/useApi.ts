import { useAuth } from "../context/AuthContext";
import { useCallback } from "react";

const BASE = "/api";

export function useApi() {
  const { apiKey, token } = useAuth();

  const headers = useCallback(
    (extra?: Record<string, string>) => {
      const h: Record<string, string> = {};
      if (apiKey) h["x-api-key"] = apiKey;
      if (token) h["Authorization"] = `Bearer ${token}`;
      return { ...h, ...extra };
    },
    [apiKey, token],
  );

  const get = useCallback(
    async (path: string) => {
      const resp = await fetch(`${BASE}${path}`, { headers: headers() });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [headers],
  );

  const post = useCallback(
    async (path: string, body?: BodyInit, contentType?: string) => {
      const h = headers(contentType ? { "Content-Type": contentType } : undefined);
      const resp = await fetch(`${BASE}${path}`, { method: "POST", headers: h, body });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [headers],
  );

  const postFormData = useCallback(
    async (path: string, formData: FormData) => {
      const h: Record<string, string> = {};
      if (apiKey) h["x-api-key"] = apiKey;
      if (token) h["Authorization"] = `Bearer ${token}`;
      const resp = await fetch(`${BASE}${path}`, {
        method: "POST",
        headers: h,
        body: formData,
      });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [apiKey, token],
  );

  const put = useCallback(
    async (path: string, body?: BodyInit, contentType?: string) => {
      const h = headers(contentType ? { "Content-Type": contentType } : undefined);
      const resp = await fetch(`${BASE}${path}`, { method: "PUT", headers: h, body });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [headers],
  );

  const del = useCallback(
    async (path: string) => {
      const resp = await fetch(`${BASE}${path}`, { method: "DELETE", headers: headers() });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [headers],
  );

  return { get, post, put, del, postFormData };
}

export class ApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body}`);
    this.status = status;
    this.body = body;
  }
}
