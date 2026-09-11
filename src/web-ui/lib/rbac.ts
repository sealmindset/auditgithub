export type RoleName =
  | "super_admin"
  | "admin"
  | "manager"
  | "analyst"
  | "user";

/** Lower number = higher privilege */
export const ROLE_LEVELS: Record<RoleName, number> = {
  super_admin: 1,
  admin: 2,
  manager: 3,
  analyst: 4,
  user: 5,
};

/**
 * Returns true when `userRole` meets or exceeds `requiredRole` in the
 * privilege hierarchy (lower number = more privileged).
 */
export function meetsMinimumRole(
  userRole: RoleName,
  requiredRole: RoleName,
): boolean {
  return (ROLE_LEVELS[userRole] ?? 99) <= (ROLE_LEVELS[requiredRole] ?? 0);
}

/**
 * Minimum role required to *see* each nav route in the sidebar.
 * Routes not listed here default to "user" (everyone can see them).
 */
export const NAV_PERMISSIONS: Record<string, RoleName> = {
  "/": "user",
  "/findings": "user",
  "/repositories": "user",
  "/zero-day/reports": "user",
  "/scheduler": "analyst",
  "/attack-surface": "analyst",
  "/zero-day": "analyst",
  "/prompts": "analyst",
  "/prompts/agents": "analyst",
  "/prompts/analytics": "analyst",
  "/prompts/audit": "admin",
  "/admin/users": "admin",
  "/settings": "admin",
  "/settings/session": "super_admin",
  "/api-audit/settings": "admin",
  "/settings/api-keys": "analyst",  // Manager + Analyst can generate API keys; User cannot
};

/** Resolve the minimum role for a given path (defaults to "user"). */
export function requiredRoleForPath(path: string): RoleName {
  return NAV_PERMISSIONS[path] ?? "user";
}
