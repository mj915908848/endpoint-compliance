import { type ReactNode } from "react";
import { ErrorNotice, Loading } from "./common";

export function Panel({
  title,
  eyebrow,
  actions,
  children,
}: {
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          {eyebrow && <span className="eyebrow">{eyebrow}</span>}
          <h2>{title}</h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Fresh({
  error,
  loading,
  children,
}: {
  error: string | null;
  loading: boolean;
  children: ReactNode;
}) {
  return error ? <ErrorNotice error={error} /> : loading ? <Loading /> : <>{children}</>;
}

export function Metric({
  label,
  value,
  tone,
  caption,
}: {
  label: string;
  value: string | number;
  tone?: string;
  caption?: string;
}) {
  return (
    <div className={`metric ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {caption && <small>{caption}</small>}
    </div>
  );
}

export function PageHeading({
  kicker,
  title,
  description,
  action,
}: {
  kicker: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">{kicker}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
