// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

interface Props {
  title: string;
  value: string | number;
  subtitle?: string;
  variant?: "default" | "success" | "warning" | "danger";
}

export function StatusCard({
  title,
  value,
  subtitle,
  variant = "default",
}: Props) {
  return (
    <div className={`status-card status-card--${variant}`}>
      <div className="status-card__title">{title}</div>
      <div className="status-card__value">{value}</div>
      {subtitle && <div className="status-card__subtitle">{subtitle}</div>}
    </div>
  );
}
