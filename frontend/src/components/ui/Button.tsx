import type { ButtonHTMLAttributes } from "react";

export type ButtonVariant = "default" | "primary" | "danger" | "small";

const VARIANT: Record<ButtonVariant, string> = {
  default: "min-h-9 px-3.5 text-[13px] border-border bg-surface-2 text-text hover:bg-border",
  primary:
    "min-h-9 px-3.5 text-[13px] border-accent bg-accent text-on-accent font-semibold hover:bg-accent/85",
  danger: "min-h-9 px-3.5 text-[13px] border-crit bg-crit text-white font-semibold hover:bg-crit/85",
  small: "min-h-[30px] px-2.5 text-[12.5px] border-border bg-surface-2 text-text hover:bg-border",
};

export function buttonClass(variant: ButtonVariant): string {
  return `inline-flex items-center justify-center gap-2 rounded-lg border font-medium whitespace-nowrap focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT[variant]}`;
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
}

export function Button({ variant = "default", type = "button", className, ...rest }: ButtonProps) {
  const extra = className === undefined ? "" : ` ${className}`;
  return <button type={type} className={`${buttonClass(variant)}${extra}`} {...rest} />;
}
