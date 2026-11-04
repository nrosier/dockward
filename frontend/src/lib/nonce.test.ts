import { describe, expect, it } from "vitest";
import { readCspNonce } from "./nonce";

describe("readCspNonce", () => {
  it("reads the nonce property, not the attribute", () => {
    // Browsers hide a nonce attribute's value after load, so the real value is
    // only on the property. Here the attribute holds a decoy and the property
    // holds the nonce: the function must return the property.
    const doc = document.implementation.createHTMLDocument("t");
    const meta = doc.createElement("meta");
    meta.setAttribute("property", "csp-nonce");
    meta.setAttribute("nonce", "attribute-decoy");
    Object.defineProperty(meta, "nonce", { value: "property-nonce", configurable: true });
    doc.head.appendChild(meta);
    expect(readCspNonce(doc)).toBe("property-nonce");
  });

  it("returns undefined when the meta element is missing", () => {
    const doc = document.implementation.createHTMLDocument("t");
    expect(readCspNonce(doc)).toBeUndefined();
  });
});
