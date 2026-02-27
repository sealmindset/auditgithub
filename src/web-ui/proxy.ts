import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/** Paths that don't require a session cookie. */
const PUBLIC_PREFIXES = ["/login", "/invite"];

/** Static / framework paths to skip entirely. */
const IGNORED_PREFIXES = ["/_next", "/favicon.ico", "/api"];

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Skip static assets and framework routes
  if (IGNORED_PREFIXES.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Allow public pages through
  if (PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  // Check for Starlette session cookie (set by FastAPI backend)
  const session = request.cookies.get("session");
  if (!session) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
