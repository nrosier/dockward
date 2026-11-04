import { useCallback, useEffect, useRef, useState } from "react";

const RESET_MS = 2000;

// Copies text to the clipboard and reports `copied` for a short time. The value
// is passed straight to the clipboard. It is never stored or logged.
export function useCopy(): { copied: boolean; copy: (value: string) => Promise<void> } {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(
    () => () => {
      if (timer.current !== undefined) {
        clearTimeout(timer.current);
      }
    },
    [],
  );

  const copy = useCallback(async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      return;
    }
    setCopied(true);
    if (timer.current !== undefined) {
      clearTimeout(timer.current);
    }
    timer.current = setTimeout(() => setCopied(false), RESET_MS);
  }, []);

  return { copied, copy };
}
