import { useEffect, useState } from "react";
import { request } from "./api";
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
    let active = true;
    if (!path) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    setState({ data: null, error: null, loading: true });
    request<T>(path)
      .then((data) => {
        if (active) setState({ data, error: null, loading: false });
      })
      .catch((error) => {
        if (active)
          setState({
            data: null,
            error: error instanceof Error ? error.message : "读取失败",
            loading: false,
          });
      });
    return () => {
      active = false;
    };
  }, [path, revision]);
  return state;
}
