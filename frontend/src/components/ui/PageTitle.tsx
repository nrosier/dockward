export function PageTitle({ title, level = 1 }: { title: string; level?: 1 | 2 }) {
  if (level === 2) {
    return <h2 className="text-lg font-semibold">{title}</h2>;
  }
  return <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>;
}
