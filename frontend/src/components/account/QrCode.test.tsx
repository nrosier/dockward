import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QrCode } from "./QrCode";

describe("QrCode", () => {
  it("draws an SVG image with a label, shapes, and no inline style", () => {
    const { container } = render(<QrCode value="otpauth://totp/x?secret=ABC" label="Scan me" />);
    const svg = screen.getByRole("img", { name: "Scan me" });
    expect(svg.tagName.toLowerCase()).toBe("svg");
    expect(container.querySelector("path")?.getAttribute("d")?.length).toBeGreaterThan(50);
    expect(container.querySelector("[style]")).toBeNull();
  });
});
