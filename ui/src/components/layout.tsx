import { type ReactNode } from "react";
import { Card, Flex, Statistic, Typography } from "antd";
import { ErrorNotice, Loading } from "./common";

export function Panel({
  title,
  actions,
  children,
}: {
  title: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Card title={title} extra={actions} className="panel">
      {children}
    </Card>
  );
}

/** Renders children only when the resource is loaded and current. */
export function Fresh({
  error,
  loading,
  children,
}: {
  error: string | null;
  loading: boolean;
  children: ReactNode;
}) {
  return error ? (
    <ErrorNotice error={error} title="数据读取失败" />
  ) : loading ? (
    <Loading />
  ) : (
    <>{children}</>
  );
}

export function Metric({
  label,
  value,
  tone,
  caption,
}: {
  label: string;
  value: string | number;
  tone?: "good" | "danger" | "warning" | "neutral";
  caption?: ReactNode;
}) {
  const color =
    tone === "good"
      ? "var(--good)"
      : tone === "danger"
        ? "var(--danger)"
        : tone === "warning"
          ? "var(--warning)"
          : undefined;
  return (
    <Card size="small" className="metric">
      <Statistic title={label} value={value} styles={{ content: { color } }} />
      {caption && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {caption}
        </Typography.Text>
      )}
    </Card>
  );
}

export function UpdatedAt({ at, refreshing }: { at: number | null; refreshing?: boolean }) {
  if (!at) return null;
  return (
    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
      {refreshing
        ? "正在刷新…"
        : `数据更新于 ${new Date(at).toLocaleTimeString("zh-CN", { hour12: false })}`}
    </Typography.Text>
  );
}

export function PageHeading({
  title,
  description,
  action,
  extra,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  extra?: ReactNode;
}) {
  return (
    <Flex className="page-heading" justify="space-between" align="end" gap={16} wrap>
      <div>
        <Typography.Title level={3} style={{ margin: 0 }}>
          {title}
        </Typography.Title>
        {description && (
          <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0" }}>
            {description}
          </Typography.Paragraph>
        )}
        {extra}
      </div>
      {action}
    </Flex>
  );
}
