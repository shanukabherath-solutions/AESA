import { NavLink, Outlet } from "react-router-dom";
import { useLoad } from "../lib/hooks";
import { api } from "../services/api";
import { useAuth } from "../services/auth";
import type { Summary } from "../types";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/repository", label: "Repository" },
  { to: "/tasks", label: "Agent tasks" },
  { to: "/changes", label: "Proposed changes", badge: true },
  { to: "/audit", label: "Audit logs" },
  { to: "/cicd", label: "CI/CD" },
];

export function Layout() {
  const { user, logout } = useAuth();
  const summary = useLoad(() => api.get<Summary>("/dashboard/summary"), [], 5000);
  const pending = summary.data?.pending_approvals ?? 0;

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-rule bg-panel">
        <div className="px-5 py-5">
          <div className="flex items-center gap-2">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#6ea8fe" strokeWidth="1.8" aria-hidden>
              <path d="M12 3 4 6v6c0 4.5 3.2 7.8 8 9 4.8-1.2 8-4.5 8-9V6l-8-3Z" /><path d="m9 12 2 2 4-4" />
            </svg>
            <span className="text-base font-semibold tracking-tight">AESA</span>
          </div>
          <p className="mt-1 text-xs text-faint">Least privilege, human approved</p>
        </div>
        <nav className="flex-1 space-y-0.5 px-3" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}
              className={({ isActive }) => `flex items-center justify-between rounded-md px-3 py-2 text-sm transition-colors ${isActive ? "bg-raised text-text" : "text-dim hover:bg-hover hover:text-text"}`}>
              {n.label}
              {n.badge && pending > 0 && <span className="rounded-full bg-warn/20 px-2 text-xs font-medium text-warn">{pending}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-rule px-4 py-3">
          <p className="text-sm font-medium">{user?.username}</p>
          <p className="text-xs text-dim">{user?.role.toLowerCase()}</p>
          <button className="mt-2 text-xs text-dim underline-offset-2 hover:text-text hover:underline" onClick={logout}>Sign out</button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-8 py-7"><Outlet /></div>
      </main>
    </div>
  );
}
