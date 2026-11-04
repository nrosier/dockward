import * as RadixScrollArea from "@radix-ui/react-scroll-area";
import type { ReactNode } from "react";
import { useNonce } from "../../lib/nonce";

// Radix ScrollArea injects a <style> element for its viewport. The nonce lets
// the CSP accept it (specs/frontend.md, "Process rules").
export function ScrollArea({ children, className }: { children: ReactNode; className?: string }) {
  const nonce = useNonce();
  return (
    <RadixScrollArea.Root className={`overflow-hidden ${className ?? ""}`}>
      <RadixScrollArea.Viewport nonce={nonce} className="size-full">
        {children}
      </RadixScrollArea.Viewport>
      <RadixScrollArea.Scrollbar orientation="vertical" className="flex w-2 touch-none select-none p-px">
        <RadixScrollArea.Thumb className="relative flex-1 rounded-full bg-border" />
      </RadixScrollArea.Scrollbar>
    </RadixScrollArea.Root>
  );
}
