/**
 * API base URL — proxied through Next.js to avoid cross-origin issues.
 * All requests go to /api/proxy/... which Next.js rewrites to the backend.
 */
export const API_BASE = "/api/proxy";


/**
 * Fetch wrapper for API calls. Same-origin via proxy, so cookies are
 * sent automatically without credentials: "include".
 */
export function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return fetch(input, {
    credentials: "include",
    ...init,
  });
}
