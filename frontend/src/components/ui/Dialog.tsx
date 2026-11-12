import * as RadixDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { t } from "../../i18n";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  // "wide" is for content such as a log. The default keeps the 32rem form width.
  size?: "default" | "wide";
  // false hides the close button and ignores Escape and outside clicks, for a step
  // that shows a value only once. The caller must offer its own way to finish.
  dismissible?: boolean;
}

const WIDTH = {
  default: "w-[min(32rem,calc(100vw-2rem))]",
  wide: "w-[min(56rem,calc(100vw-2rem))]",
};

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  size = "default",
  dismissible = true,
}: DialogProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={(next) => (dismissible || next ? onOpenChange(next) : undefined)}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-40 bg-black/60" />
        <RadixDialog.Content
          {...(dismissible
            ? {}
            : {
                onEscapeKeyDown: (event: Event) => event.preventDefault(),
                onPointerDownOutside: (event: Event) => event.preventDefault(),
                onInteractOutside: (event: Event) => event.preventDefault(),
              })}
          {...(description === undefined ? { "aria-describedby": undefined } : {})}
          className={`fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] ${WIDTH[size]} -translate-x-1/2 -translate-y-1/2 flex-col gap-4 overflow-y-auto rounded-xl border border-border bg-surface p-6`}
        >
          <div className="flex items-start justify-between gap-4">
            <RadixDialog.Title className="text-base font-semibold">{title}</RadixDialog.Title>
            {dismissible ? (
              <RadixDialog.Close
                aria-label={t("common.close")}
                className="rounded-md p-1 text-muted hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              >
                <X aria-hidden="true" size={16} />
              </RadixDialog.Close>
            ) : null}
          </div>
          {description === undefined ? null : (
            <RadixDialog.Description className="text-[13px] text-muted">{description}</RadixDialog.Description>
          )}
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}
