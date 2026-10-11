export type LineKind = "add" | "del" | "ctx" | "hunk";
export interface DiffLine { kind: LineKind; text: string; oldNo: number | null; newNo: number | null }
export interface DiffFile { path: string; lines: DiffLine[]; additions: number; deletions: number }

/** Parse a unified diff (as produced by `git diff`) into per-file line lists with line numbers. */
export function parseUnifiedDiff(diff: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | null = null;
  let o = 0, n = 0, inHunk = false;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("diff --git ")) {
      const m = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
      cur = { path: m ? m[2] : raw.slice(11), lines: [], additions: 0, deletions: 0 };
      files.push(cur); inHunk = false; continue;
    }
    if (!cur) continue;
    const h = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (h) { o = +h[1]; n = +h[2]; inHunk = true; cur.lines.push({ kind: "hunk", text: raw, oldNo: null, newNo: null }); continue; }
    if (!inHunk) continue; // file headers (---, +++, index, mode)
    if (raw.startsWith("+")) { cur.lines.push({ kind: "add", text: raw.slice(1), oldNo: null, newNo: n++ }); cur.additions++; }
    else if (raw.startsWith("-")) { cur.lines.push({ kind: "del", text: raw.slice(1), oldNo: o++, newNo: null }); cur.deletions++; }
    else if (raw.startsWith("\\")) continue;
    else if (raw.length) { cur.lines.push({ kind: "ctx", text: raw.slice(1), oldNo: o++, newNo: n++ }); }
  }
  return files;
}
