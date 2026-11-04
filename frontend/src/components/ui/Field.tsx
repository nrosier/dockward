import type { ReactNode } from "react";

interface FieldProps {
  id: string;
  label: string;
  help?: string;
  error?: string;
  children: ReactNode;
}

// Stacked: label, optional help, the control, then the error
// (specs/frontend.md, "Settings rows"). The control gets `id` from the caller.
export function Field({ id, label, help, error, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] font-semibold">
        {label}
      </label>
      {help === undefined ? null : (
        <p id={`${id}-help`} className="text-[12.5px] text-muted">
          {help}
        </p>
      )}
      {children}
      {error === undefined ? null : (
        <p id={`${id}-error`} role="alert" className="text-[12.5px] text-crit-ink">
          {error}
        </p>
      )}
    </div>
  );
}
