import { setNonce } from "get-nonce";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { readCspNonce } from "./lib/nonce";
import { applyTheme, getTheme } from "./lib/preferences";
import "./index.css";

// Before the first render: apply the stored theme, and hand the CSP nonce to
// get-nonce, which react-style-singleton (Radix Dialog's scroll lock) reads.
applyTheme(getTheme());
const nonce = readCspNonce(document);
if (nonce !== undefined) {
  setNonce(nonce);
}

const root = document.getElementById("root");
if (root === null) {
  throw new Error("Missing #root element");
}

createRoot(root).render(
  <StrictMode>
    <App nonce={nonce} />
  </StrictMode>,
);
