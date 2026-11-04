import { useSearchParams } from "react-router";
import { t } from "../../i18n";
import { useMe } from "../../lib/session";

const BASE =
  "min-h-8 cursor-pointer px-3 text-[12.5px] font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent";
const ON = "bg-surface-2 text-text";
const OFF = "bg-transparent text-muted";

// "My mappings / All mappings", for admins only. "All mappings" is `scope=all`
// in the URL, so a reload or a shared link keeps the choice.
export function ScopeToggle() {
  const me = useMe();
  const [params, setParams] = useSearchParams();
  if (me.data?.role !== "admin") {
    return null;
  }
  const all = params.get("scope") === "all";
  const choose = (next: boolean) => {
    const updated = new URLSearchParams(params);
    if (next) {
      updated.set("scope", "all");
    } else {
      updated.delete("scope");
    }
    updated.delete("page");
    setParams(updated);
  };
  return (
    <fieldset
      aria-label={t("scope.label")}
      className="m-0 inline-flex min-w-0 overflow-hidden rounded-lg border border-border p-0"
    >
      <button type="button" aria-pressed={!all} onClick={() => choose(false)} className={`${BASE} ${all ? OFF : ON}`}>
        {t("scope.mine")}
      </button>
      <button type="button" aria-pressed={all} onClick={() => choose(true)} className={`${BASE} ${all ? ON : OFF}`}>
        {t("scope.all")}
      </button>
    </fieldset>
  );
}
