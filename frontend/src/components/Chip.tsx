import type { CSSProperties, ReactNode } from "react";

export function Chip({
  on, color, onClick, title, children,
}: { on: boolean; color?: string; onClick: () => void; title?: string; children: ReactNode }) {
  return (
    <button
      type="button"
      className={`chip${on ? " on" : ""}`}
      style={color ? ({ "--chip": color } as CSSProperties) : undefined}
      aria-pressed={on}
      title={title}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

export function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}
