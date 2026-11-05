import { useEffect, useState } from "react";

// The value after it has stopped changing for `delayMs`. A search box uses it
// so one request is not sent per keystroke (the picker routes allow 60 a minute).
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return settled;
}
