import { useEffect, useState, type ReactNode } from "react";
import { t } from "../../i18n";
import {
  SEVERITIES,
  STATUSES,
  type CveFilterState,
  FIXES,
  namespaceOf,
  type FixValue,
  type HasIssue,
  type SeverityValue,
  type StatusValue,
} from "../../lib/cveFilters";
import type { MappingTag } from "../../types/api";
import type { Source } from "../../types/sources";
import { Combobox } from "../ui/Combobox";
import { INPUT } from "../mappings/styles";

const DEBOUNCE_MS = 300;
const GROUP_LABEL = "mr-0.5 text-[11px] font-semibold tracking-[0.06em] text-muted uppercase";

// Filled with the tone when on, an outline when off. The dot is hollow when off, so the
// state is not colour alone.
const TONE: Record<string, string> = {
  CRITICAL: "text-crit-ink bg-crit/12 border-crit/45",
  HIGH: "text-high-ink bg-high/12 border-high/45",
  MEDIUM: "text-med-ink bg-med/10 border-med/40",
  LOW: "text-low-ink bg-low/12 border-low/45",
  accepted: "text-accent bg-accent/15 border-accent/45",
  fixed: "text-ok-ink bg-ok/12 border-ok/45",
  neutral: "text-text bg-text/10 border-text",
};

function FilterPill({ on, tone, label, onClick }: { on: boolean; tone: string; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={`inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-full border px-[11px] text-[11px] leading-none font-semibold tracking-[0.05em] whitespace-nowrap uppercase focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
        on ? (TONE[tone] ?? TONE.neutral) : "border-muted bg-transparent text-muted"
      }`}
    >
      <span aria-hidden="true" className={`size-1.5 rounded-full ${on ? "bg-current" : "border border-current"}`} />
      {label}
    </button>
  );
}

function Group({ label, children }: { label: string; children: ReactNode }) {
  return (
    // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role -- a fieldset cannot sit in this wrapping flex row with the visible label
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-2">
      <span aria-hidden="true" className={GROUP_LABEL}>
        {label}
      </span>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// The search box reports its value 300 ms after the last keystroke. Clear reports at once.
function SearchField({ value, onCommit }: { value: string; onCommit: (value: string) => void }) {
  const [draft, setDraft] = useState(value);
  useEffect(() => {
    setDraft(value);
  }, [value]);
  useEffect(() => {
    if (draft === value) {
      return;
    }
    const timer = setTimeout(() => onCommit(draft), DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- onCommit is recreated each render and only reads current params
  }, [draft, value]);
  return (
    <div className="relative">
      <input
        type="search"
        aria-label={t("cves.filter.search")}
        value={draft}
        placeholder={t("cves.filter.searchPlaceholder")}
        onChange={(event) => setDraft(event.target.value)}
        className={`${INPUT} pr-24 [&::-webkit-search-cancel-button]:hidden`}
      />
      {draft === "" ? null : (
        <button
          type="button"
          onClick={() => {
            setDraft("");
            onCommit("");
          }}
          className="absolute top-[3px] right-1 min-h-[30px] cursor-pointer rounded-lg border border-border bg-surface-2 px-2.5 text-[12.5px] font-medium text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          {t("cves.filter.clear")}
        </button>
      )}
    </div>
  );
}

interface CveFilterBarProps {
  state: CveFilterState;
  // The image sources in scope. Each one is an option of the Mapping filter (#323).
  sources: Source[];
  // Tracked tags of the chosen source, when one is chosen.
  tags: MappingTag[];
  // Sets or clears (value "") the URL parameters named in the patch.
  onChange: (patch: Record<string, string>) => void;
}

function toggle<T extends string>(selected: T[], value: T, all: readonly T[]): T[] {
  const next = selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value];
  return all.filter((item) => next.includes(item));
}

export function CveFilterBar({ state, sources, tags, onChange }: CveFilterBarProps) {
  const paths = sources.map((source) => source.repository);
  const namespaces = Array.from(new Set(paths.map(namespaceOf))).sort();
  const repositories = Array.from(
    new Set(paths.filter((path) => state.namespace === "" || namespaceOf(path) === state.namespace)),
  ).sort();

  function pickSeverity(value: SeverityValue) {
    onChange({ severity: toggle(state.severities, value, SEVERITIES).join(",") });
  }
  function pickStatus(value: StatusValue) {
    const next = toggle(state.statuses, value, STATUSES);
    // The last Status pill stays on; Open alone is the default and leaves the URL.
    if (next.length > 0) {
      onChange({ status: next.join(",") === "open" ? "" : next.join(",") });
    }
  }
  function pickIssue(value: Exclude<HasIssue, "">) {
    onChange({ has_issue: state.hasIssue === value ? "" : value });
  }
  function pickFix(value: FixValue) {
    onChange({ fix: toggle(state.fixes, value, FIXES).join(",") });
  }
  function pickNamespace(namespace: string) {
    // A repository that is not in the chosen namespace is cleared with it.
    const stillFits = state.repository === "" || namespace === "" || namespaceOf(state.repository) === namespace;
    onChange({ namespace, ...(stillFits ? {} : { repository: "" }) });
  }

  return (
    <search aria-label={t("cves.filter.group")} className="flex flex-col gap-3 rounded-[10px] border border-border bg-surface px-4 py-3.5">
      <SearchField value={state.q} onCommit={(value) => onChange({ q: value })} />
      <div className="flex flex-col gap-3 min-[1024px]:flex-row min-[1024px]:flex-wrap min-[1024px]:gap-x-7">
        <Group label={t("cves.filter.severity")}>
          {SEVERITIES.map((value) => (
            <FilterPill
              key={value}
              on={state.severities.includes(value)}
              tone={value}
              label={value}
              onClick={() => pickSeverity(value)}
            />
          ))}
        </Group>
        <Group label={t("cves.filter.status")}>
          {STATUSES.map((value) => (
            <FilterPill
              key={value}
              on={state.statuses.includes(value)}
              tone={value === "open" ? "neutral" : value}
              label={t(`cves.status.${value}`)}
              onClick={() => pickStatus(value)}
            />
          ))}
        </Group>
        <Group label={t("cves.filter.issue")}>
          <FilterPill
            on={state.hasIssue === "true"}
            tone="neutral"
            label={t("cves.filter.hasIssue")}
            onClick={() => pickIssue("true")}
          />
          <FilterPill
            on={state.hasIssue === "false"}
            tone="neutral"
            label={t("cves.filter.noIssue")}
            onClick={() => pickIssue("false")}
          />
        </Group>
        <Group label={t("cves.filter.fix")}>
          <FilterPill
            on={state.fixes.includes("available")}
            tone="neutral"
            label={t("cves.filter.fixAvailable")}
            onClick={() => pickFix("available")}
          />
          <FilterPill
            on={state.fixes.includes("none")}
            tone="neutral"
            label={t("cves.filter.noFix")}
            onClick={() => pickFix("none")}
          />
        </Group>
      </div>
      <div className="grid grid-cols-1 gap-3 min-[1024px]:grid-cols-4">
        <Combobox
          id="cve-namespace"
          label={t("cves.filter.namespace")}
          value={state.namespace}
          options={namespaces.map((namespace) => ({ value: namespace, label: namespace }))}
          allLabel={t("cves.filter.allNamespaces")}
          onChange={pickNamespace}
        />
        <Combobox
          id="cve-repository"
          label={t("cves.filter.repository")}
          value={state.repository}
          options={repositories.map((repository) => ({ value: repository, label: repository }))}
          allLabel={t("cves.filter.allRepositories")}
          onChange={(repository) => onChange({ repository })}
        />
        <Combobox
          id="cve-tag"
          label={t("cves.filter.tag")}
          value={state.tag}
          options={tags.map((tag) => ({ value: tag.image_tag, label: tag.image_tag }))}
          allLabel={t("cves.filter.allTags")}
          allowCustom
          onChange={(tag) => onChange({ tag })}
        />
        <Combobox
          id="cve-mapping"
          label={t("cves.filter.mapping")}
          value={state.mapping}
          options={sources.map((source) => ({ value: source.id, label: source.repository }))}
          allLabel={t("cves.filter.allMappings")}
          allAsValue
          onChange={(mapping) => onChange({ mapping })}
        />
      </div>
    </search>
  );
}
