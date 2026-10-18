import { type ReactNode } from "react";
import { Card, Flex, Typography } from "antd";
import { ErrorNotice, Loading } from "./common";

export function Panel({
  title,
  actions,
  children,
  id,
}: {
  title: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  return (
    <Card title={title} extra={actions} className="panel" id={id}>
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

/** A count with a colored dot for its meaning; the number itself takes the color only when it is not zero. */
export function Metric({
  label,
  value,
  tone,
  caption,
  onClick,
}: {
  label: string;
  value: string | number;
  tone?: "good" | "danger" | "warning" | "neutral";
  caption?: ReactNode;
  /** Makes the card a link to the list it counts. */
  onClick?: () => void;
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
    <Card
      size="small"
      className={onClick ? "metric metric-link" : "metric"}
      hoverable={!!onClick}
      onClick={onClick}
      role={onClick ? "link" : undefined}
      tabIndex={onClick ? 0 : undefined}
      aria-label={onClick ? `${label} ${value}，查看终端` : undefined}
      onKeyDown={onClick ? (e) => (e.key === "Enter" || e.key === " ") && onClick() : undefined}
    >
      <div className="metric-label">
        <span className="metric-dot" style={color ? { background: color } : undefined} />
        {label}
      </div>
      <div className="metric-value" style={color && value !== 0 ? { color } : undefined}>
        {value}
      </div>
      {caption && <div className="metric-caption">{caption}</div>}
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
