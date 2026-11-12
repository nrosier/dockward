import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QrCode } from "./QrCode";

// The server's qr_svg. It is a QR image only, with no text nodes.
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4"><path d="M0 0h1v1h-1z"/></svg>';

describe("QrCode", () => {
  it("renders the server SVG inside a labelled image role with no inline style", () => {
    const { container } = render(<QrCode svg={SVG} label="Scan me" />);
    const frame = screen.getByRole("img", { name: "Scan me" });
    expect(frame.querySelector("svg path")?.getAttribute("d")).toBe("M0 0h1v1h-1z");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("adds no text of its own inside the QR frame", () => {
    render(<QrCode svg={SVG} label="Scan me" />);
    const frame = screen.getByRole("img", { name: "Scan me" });
    expect(frame.textContent).toBe("");
    expect(frame.querySelector("text")).toBeNull();
  });
});
