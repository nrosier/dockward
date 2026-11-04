import { createContext, useContext } from "react";

// Reads the CSP nonce that the backend writes into index.html on every HTML
// response. The `nonce` property is used, not getAttribute: browsers hide the
// attribute value once the document has loaded (specs/security.md).
export function readCspNonce(doc: Document): string | undefined {
  return (doc.querySelector('meta[property="csp-nonce"]') as HTMLMetaElement | null)?.nonce || undefined;
}

export const NonceContext = createContext<string | undefined>(undefined);

export function useNonce(): string | undefined {
  return useContext(NonceContext);
}
