import { describe, expect, it } from "vitest";
import { parseUnifiedDiff } from "./diff";
import { label, pipelineIndex, timeAgo, toneOf } from "./format";

const DIFF = `diff --git a/app/auth.py b/app/auth.py
index 1..2 100644
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,4 +1,4 @@
 import hashlib
-SECRET = "x"
+SECRET = env()
 def f():
@@ -10,2 +10,3 @@ def g():
 a
+b
 c
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,1 @@
+print(1)
`;

describe("parseUnifiedDiff", () => {
  const files = parseUnifiedDiff(DIFF);
  it("splits files and counts changes", () => {
    expect(files.map((f) => f.path)).toEqual(["app/auth.py", "new.py"]);
    expect(files[0]).toMatchObject({ additions: 2, deletions: 1 });
    expect(files[1]).toMatchObject({ additions: 1, deletions: 0 });
  });
  it("tracks old/new line numbers per hunk", () => {
    const l = files[0].lines;
    expect(l.find((x) => x.kind === "del")).toMatchObject({ oldNo: 2, newNo: null });
    expect(l.filter((x) => x.kind === "add")[1]).toMatchObject({ newNo: 11 });
    expect(l.filter((x) => x.kind === "hunk")).toHaveLength(2);
  });
  it("handles empty input", () => expect(parseUnifiedDiff("")).toEqual([]));
});

describe("format helpers", () => {
  it("maps statuses to tones", () => {
    expect(toneOf("PASSED")).toBe("ok");
    expect(toneOf("DENIED")).toBe("deny");
    expect(toneOf("AWAITING_APPROVAL")).toBe("warn");
    expect(toneOf("???")).toBe("dim");
  });
  it("labels", () => expect(label("READY_FOR_DEPLOYMENT")).toBe("Ready for deployment"));
  it("time ago", () => {
    const now = Date.parse("2026-10-05T12:00:00Z");
    expect(timeAgo("2026-10-05T11:59:30Z", now)).toBe("30s ago");
    expect(timeAgo("2026-10-05T10:00:00Z", now)).toBe("2h ago");
    expect(timeAgo(null)).toBe("never");
  });
  it("pipeline index", () => {
    expect(pipelineIndex("AWAITING_APPROVAL")).toBe(2);
    expect(pipelineIndex("CI_PASSED")).toBe(pipelineIndex("CI_RUNNING"));
    expect(pipelineIndex("FAILED_SAFELY")).toBe(-1);
  });
});
