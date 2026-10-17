import { QueryClient, useQuery, useQueryClient } from "@tanstack/react-query";
import { request } from "./api";

export const POLL_MS = 30_000;
const TIMEOUT_MS = 12_000;
export const TIMEOUT_MESSAGE = "刷新超时，当前状态无法判断";

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchInterval: POLL_MS,
        refetchOnWindowFocus: true,
        refetchIntervalInBackground: false,
      },
    },
  });
}

// Abort a request when TanStack cancels it or when the server does not answer in time.
async function fetchWithTimeout<T>(path: string, signal: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), TIMEOUT_MS);
  const cancel = () => controller.abort();
  signal.addEventListener("abort", cancel);
  try {
    return await request<T>(path, { signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted && !signal.aborted) throw new Error(TIMEOUT_MESSAGE);
    throw error;
  } finally {
    window.clearTimeout(timer);
    signal.removeEventListener("abort", cancel);
  }
}

export interface Resource<T> {
  data: T | null;
  /**
   * The last data read, kept through failed refreshes. Only for what the administrator is editing or that names
   * the object on screen; never for a verdict or state, which must not look current when it cannot be confirmed.
   */
  lastData: T | null;
  error: string | null;
  /** First load only; background refreshes keep the current data on screen. */
  loading: boolean;
  refreshing: boolean;
  updatedAt: number | null;
}

/**
 * Polls a management API path. Data stays visible while a refresh is in flight so the page
 * does not jump, but a failed or timed-out refresh drops it: a verdict the server can no
 * longer confirm must not stay on screen as if it were current.
 */
export function useResource<T>(path: string | null): Resource<T> {
  const query = useQuery({
    queryKey: [path],
    queryFn: ({ signal }) => fetchWithTimeout<T>(path!, signal),
    enabled: !!path,
  });
  const failed = query.isError;
  return {
    data: failed ? null : (query.data ?? null),
    lastData: query.data ?? null,
    error: failed ? (query.error instanceof Error ? query.error.message : "读取失败") : null,
    loading: !!path && query.isPending && !failed,
    refreshing: query.isFetching && !query.isPending,
    updatedAt: failed || !query.dataUpdatedAt ? null : query.dataUpdatedAt,
  };
}

/** Re-reads every visible resource, e.g. after an action changed server state. */
export function useRefresh() {
  const client = useQueryClient();
  return () => void client.invalidateQueries();
}
