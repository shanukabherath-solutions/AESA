import { useMemo, useState } from "react";
import { Empty, ErrorNote, Mono, PageHeader, Panel, Stat } from "../components/ui";
import { useLoad } from "../lib/hooks";
import { api } from "../services/api";
import { useAuth } from "../services/auth";
import type { Repo, RepoStats } from "../types";

interface Node { name: string; path: string; children: Map<string, Node>; file: boolean }

function build(files: string[]): Node {
  const root: Node = { name: "", path: "", children: new Map(), file: false };
  for (const f of files) {
    let cur = root;
    f.split("/").forEach((part, i, arr) => {
      const path = arr.slice(0, i + 1).join("/");
      if (!cur.children.has(part)) cur.children.set(part, { name: part, path, children: new Map(), file: i === arr.length - 1 });
      cur = cur.children.get(part)!;
    });
  }
  return root;
}

function Tree({ node, depth = 0 }: { node: Node; depth?: number }) {
  const kids = [...node.children.values()].sort((a, b) => Number(a.file) - Number(b.file) || a.name.localeCompare(b.name));
  return (
    <ul>
      {kids.map((k) => (
        <li key={k.path}>
          <div className="flex items-center gap-2 py-0.5 font-mono text-xs" style={{ paddingLeft: depth * 16 }}>
            <span className="text-faint">{k.file ? "·" : "▸"}</span>
            <span className={k.file ? "text-text" : "text-dim"}>{k.name}{k.file ? "" : "/"}</span>
          </div>
          {!k.file && <Tree node={k} depth={depth + 1} />}
        </li>
      ))}
    </ul>
  );
}

export function RepositoryPage() {
  const { can } = useAuth();
  const repos = useLoad(() => api.get<Repo[]>("/repositories"), []);
  const [sel, setSel] = useState<number | null>(null);
  const repoId = sel ?? repos.data?.[0]?.id ?? null;
  const repo = repos.data?.find((r) => r.id === repoId);
  const stats = useLoad(() => (repoId && can("inspect") ? api.get<RepoStats>(`/repositories/${repoId}/stats`) : Promise.resolve(null)), [repoId]);
  const tree = useLoad(() => (repoId && can("inspect") ? api.get<{ files: string[] }>(`/repositories/${repoId}/tree`) : Promise.resolve(null)), [repoId]);
  const root = useMemo(() => build(tree.data?.files ?? []), [tree.data]);

  return (
    <>
      <PageHeader title="Repository" subtitle="Only permitted files are visible to the agent. Secrets and .git are never listed."
        action={repos.data && repos.data.length > 1 ? <select className="input w-56" value={repoId ?? ""} onChange={(e) => setSel(+e.target.value)}>{repos.data.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select> : undefined} />
      <ErrorNote message={repos.error} />
      {!repo && !repos.loading && <Empty>No repositories registered. An admin can register one under REPOS_ROOT.</Empty>}
      {repo && (
        <div className="grid gap-5 lg:grid-cols-3">
          <div className="space-y-5 lg:col-span-1">
            <Panel title="Statistics">
              {!can("inspect") ? <p className="text-dim">Your role cannot inspect repositories.</p> : stats.data ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3"><Stat name="Permitted files" value={stats.data.file_count} /><Stat name="Test files" value={stats.data.test_files.length} /></div>
                  <div><p className="text-xs text-dim">Languages</p><p>{Object.entries(stats.data.languages).map(([k, v]) => `${k} (${v})`).join(", ") || "none"}</p></div>
                  <div><p className="text-xs text-dim">Frameworks</p><p>{stats.data.frameworks.join(", ") || "none detected"}</p></div>
                </div>
              ) : <p className="text-dim">Loading…</p>}
            </Panel>
            <Panel title="Protection">
              <dl className="space-y-2 text-sm">
                <div><dt className="text-xs text-dim">Default branch</dt><dd><Mono>{repo.default_branch}</Mono></dd></div>
                <div><dt className="text-xs text-dim">Protected branches</dt><dd className="flex flex-wrap gap-1">{repo.protected_branches.map((b) => <Mono key={b}>{b}</Mono>)}</dd></div>
                <div><dt className="text-xs text-dim">Agent cannot modify</dt><dd className="flex flex-wrap gap-1">{repo.protected_paths.map((p) => <Mono key={p}>{p}</Mono>)}</dd></div>
                <div><dt className="text-xs text-dim">GitHub</dt><dd>{repo.github_repo ?? "not connected (local git flow)"}</dd></div>
              </dl>
            </Panel>
          </div>
          <Panel title="Directory tree" className="lg:col-span-2">
            {tree.data ? <Tree node={root} /> : <p className="text-dim">{can("inspect") ? "Loading…" : "Not permitted."}</p>}
          </Panel>
        </div>
      )}
    </>
  );
}
