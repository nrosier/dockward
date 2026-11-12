// Renders the enrolment QR that the server returns as qr_svg. The SVG comes from
// our own API response, so it is injected as HTML; the wrapper adds nothing else.
// The server draws dark modules on a white field, so both themes scan the same.
export function QrCode({ svg, label }: { svg: string; label: string }) {
  return (
    <div
      // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role -- an <img> cannot hold inline SVG without a data: or blob: URL, which the CSP blocks
      role="img"
      aria-label={label}
      className="size-44 shrink-0 overflow-hidden rounded-lg [&>svg]:size-full"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
