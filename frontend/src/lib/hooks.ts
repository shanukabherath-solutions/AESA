import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../services/api";

export interface Loaded<T> { data: T | null; error: string | null; loading: boolean; reload: () => void }

/** Fetch on mount (and when deps change); optionally poll while `pollMs` is set. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], pollMs?: number | null): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(() => {
    fnRef.current()
      .then((d) => { setData(d); setError(null); })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.headline : "Request failed"))
      .finally(() => setLoading(false));
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setLoading(true); run(); }, [...deps, run]);
  useEffect(() => {
    if (!pollMs) return;
    const id = setInterval(run, pollMs);
    return () => clearInterval(id);
  }, [pollMs, run]);

  return { data, error, loading, reload: run };
}
