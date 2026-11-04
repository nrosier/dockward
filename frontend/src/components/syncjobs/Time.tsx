import { formatWhen } from "./dates";

export function Time({ iso }: { iso: string | null }) {
  if (iso === null) {
    return null;
  }
  return (
    <time dateTime={iso} title={iso} className="whitespace-nowrap">
      {formatWhen(iso)}
    </time>
  );
}
