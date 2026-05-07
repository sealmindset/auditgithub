/**
 * Reverse proxy API route for forwarding requests to the FastAPI backend.
 *
 * Handles:
 * - Cookie forwarding (session cookies for auth)
 * - Following internal redirects (307 trailing slash redirects)
 * - Preserving request method, headers, and body
 */

const API_BACKEND = process.env.API_BASE || "http://api:8000";

async function proxyRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  // Extract the path after /api/proxy/
  const proxyPath = url.pathname.replace(/^\/api\/proxy/, "");
  const targetUrl = `${API_BACKEND}${proxyPath}${url.search}`;



  // Forward relevant headers
  const headers = new Headers();
  const forwardHeaders = [
    "cookie",
    "content-type",
    "accept",
    "authorization",
    "x-organization-id",
    "x-organization-name",
    "x-api-key",
    "x-request-id",
  ];
  for (const h of forwardHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h, val);
  }
  // Pass along the original host for CORS/origin checks
  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));

  // Build fetch options
  const fetchOptions: RequestInit = {
    method: request.method,
    headers,
    redirect: "manual", // Handle redirects ourselves
  };

  // Forward body for non-GET/HEAD requests
  if (request.method !== "GET" && request.method !== "HEAD") {
    fetchOptions.body = await request.arrayBuffer();
  }

  let response: Response;
  try {
    response = await fetch(targetUrl, fetchOptions);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return new Response(
      JSON.stringify({ detail: `Backend unavailable: ${message}` }),
      {
        status: 502,
        headers: { "content-type": "application/json" },
      }
    );
  }

  // Follow redirects internally (e.g. FastAPI trailing slash 307)
  let redirectCount = 0;
  while (
    redirectCount < 5 &&
    [301, 302, 307, 308].includes(response.status)
  ) {
    const location = response.headers.get("location");
    if (!location) break;

    // Resolve relative redirects against the target URL
    const redirectUrl = new URL(location, targetUrl);

    // Only follow redirects to the same backend
    const backendOrigin = new URL(API_BACKEND).origin;
    if (redirectUrl.origin !== backendOrigin) break;

    try {
      response = await fetch(redirectUrl.toString(), {
        ...fetchOptions,
        // Redirects may change method (301/302 → GET), 307/308 preserve method
        method: [307, 308].includes(response.status)
          ? request.method
          : "GET",
        redirect: "manual",
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      return new Response(
        JSON.stringify({ detail: `Backend unavailable during redirect: ${message}` }),
        {
          status: 502,
          headers: { "content-type": "application/json" },
        }
      );
    }
    redirectCount++;
  }

  // Build response headers, forwarding Set-Cookie and other relevant headers
  const responseHeaders = new Headers();
  const passthroughHeaders = [
    "content-type",
    "content-length",
    "content-disposition",
    "cache-control",
    "etag",
    "last-modified",
    "x-request-id",
  ];
  for (const h of passthroughHeaders) {
    const val = response.headers.get(h);
    if (val) responseHeaders.set(h, val);
  }

  // Forward all Set-Cookie headers (critical for session management)
  const setCookies = response.headers.getSetCookie?.() ?? [];
  for (const cookie of setCookies) {
    responseHeaders.append("set-cookie", cookie);
  }

  // Forward Location header for any redirect response (301-308)
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location") || "";
    if (location) {
      // Rewrite backend-internal URLs to proxy URLs
      const backendOrigin = new URL(API_BACKEND).origin;
      if (location.startsWith(backendOrigin)) {
        const path = location.slice(backendOrigin.length);
        responseHeaders.set("location", `/api/proxy${path}`);
      } else if (location.startsWith("/")) {
        responseHeaders.set("location", `/api/proxy${location}`);
      } else {
        // External URLs (e.g. http://localhost:3000, mock-oidc) pass through as-is
        responseHeaders.set("location", location);
      }
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
export const HEAD = proxyRequest;
export const OPTIONS = proxyRequest;
