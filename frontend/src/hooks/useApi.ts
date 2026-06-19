import { useAuth } from "../context/AuthContext";
import { useCallback } from "react";

const BASE = "/api";

export function useApi() {
  const { apiKey } = useAuth();

  const headers = useCallback(
    (extra?: Record<string, string>) => ({
      "x-api-key": apiKey ?? "",
      ...extra,
    }),
    [apiKey],
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
      const resp = await fetch(`${BASE}${path}`, {
        method: "POST",
        headers: { "x-api-key": apiKey ?? "" },
        body: formData,
      });
      if (!resp.ok) throw new ApiError(resp.status, await resp.text());
      return resp;
    },
    [apiKey],
  );

  return { get, post, postFormData };
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
