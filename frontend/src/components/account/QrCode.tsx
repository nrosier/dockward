import qrcode from "qrcode-generator";
import { useMemo } from "react";

const QUIET_ZONE = 4;

// Draws a QR code in the browser as one SVG path. The value (an otpauth URI that
// holds the secret) never leaves the page. No inline style, so the CSP holds.
// Always dark modules on a white field, in both themes, so every scanner reads it.
export function QrCode({ value, label }: { value: string; label: string }) {
  const { size, path } = useMemo(() => {
    const code = qrcode(0, "M");
    code.addData(value);
    code.make();
    const count = code.getModuleCount();
    const parts: string[] = [];
    for (let row = 0; row < count; row += 1) {
      for (let col = 0; col < count; col += 1) {
        if (code.isDark(row, col)) {
          parts.push(`M${col + QUIET_ZONE} ${row + QUIET_ZONE}h1v1h-1z`);
        }
      }
    }
    return { size: count + QUIET_ZONE * 2, path: parts.join("") };
  }, [value]);

  return (
    <svg
      // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role -- an <img> needs a data: or blob: URL, which the CSP blocks
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className="size-44 shrink-0 rounded-lg"
    >
      <rect width={size} height={size} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
