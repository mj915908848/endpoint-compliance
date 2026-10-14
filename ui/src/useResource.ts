import { useEffect, useState } from "react";
import { request } from "./api";

// A visible PASS depends on server time and heartbeat. Expire it before every poll.
export function useResource<T>(
  path: string | null,
  revision = 0,
): { data: T | null; error: string | null; loading: boolean } {
  const [state, setState] = useState<{
    data: T | null;
    error: string | null;
    loading: boolean;
  }>({ data: null, error: null, loading: !!path });
  useEffect(() => {
    if (!path) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    let active = true;
    let generation = 0;
    let inFlight: AbortController | null = null;
    function load() {
      const version = ++generation;
      inFlight?.abort();
      const controller = new AbortController();
      inFlight = controller;
      setState({ data: null, error: null, loading: true });
      const deadline = window.setTimeout(() => controller.abort(), 12_000);
      request<T>(path!, { signal: controller.signal })
        .then((data) => {
          if (active && version === generation)
            setState({ data, error: null, loading: false });
        })
        .catch((error) => {
          if (active && version === generation)
            setState({
              data: null,
              error: controller.signal.aborted
                ? "刷新超时，当前状态无法判断"
                : error instanceof Error
                  ? error.message
                  : "读取失败",
              loading: false,
            });
        })
        .finally(() => window.clearTimeout(deadline));
    }
    const onVisible = () => { if (document.visibilityState === "visible") load(); };
    const onFocus = () => load();
    load();
    const poll = window.setInterval(load, 30_000);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onFocus);
    return () => {
      active = false;
      inFlight?.abort();
      window.clearInterval(poll);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onFocus);
    };
  }, [path, revision]);
  return state;
}
