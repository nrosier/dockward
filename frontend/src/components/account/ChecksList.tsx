import { t, type MessageKey } from "../../i18n";
import type { CheckResult } from "../../types/api";

const NAMES: Record<string, MessageKey> = {
  harbor_robot: "credentials.check.harbor_robot",
  github_repo: "credentials.check.github_repo",
  github_code_scanning: "credentials.check.github_code_scanning",
  github_issues: "credentials.check.github_issues",
  github_repository_visible: "credentials.check.github_repository_visible",
};

// The server sends a catalog key as the detail when the text is fixed.
function detailOf(check: CheckResult): string {
  return check.detail === "credentials.test.noRepository" ? t("credentials.test.noRepository") : check.detail;
}

function nameOf(check: CheckResult): string {
  const key = NAMES[check.name];
  return key === undefined ? check.name : t(key);
}

// One row per check: its name, pass/warning/fail as text, and the server detail.
// The detail is rendered as escaped text only.
export function ChecksList({ checks }: { checks: CheckResult[] }) {
  return (
    <ul className="m-0 flex list-none flex-col p-0">
      {checks.map((check) => {
        const state = !check.ok ? "fail" : check.warning ? "warning" : "pass";
        const tone = state === "fail" ? "text-crit-ink" : state === "warning" ? "text-high-ink" : "text-ok-ink";
        return (
          <li key={check.name} className="flex flex-col gap-0.5 border-t border-border py-2.5">
            <div className="text-[13px] font-medium">
              {nameOf(check)}{" "}
              <span className={`font-semibold ${tone}`}>
                {"· "}
                {t(`credentials.state.${state}`)}
              </span>
            </div>
            <div className="text-[12.5px] text-muted">{detailOf(check)}</div>
          </li>
        );
      })}
    </ul>
  );
}
