import { useState } from "react";
import { CardHeading, INPUT, Segmented } from "../components/admin/parts";
import { Card } from "../components/ui/Card";
import { Field } from "../components/ui/Field";
import { t } from "../i18n";
import { getLanguage, getTheme, setLanguage, setTheme, type Language, type Theme } from "../lib/preferences";

// Appearance tab: theme and language. Saved in this browser only.
export function AppearanceTab() {
  const [theme, setThemeState] = useState<Theme>(getTheme);
  const [language, setLanguageState] = useState<Language>(getLanguage);

  return (
    <div className="flex flex-col gap-5">
      <Card className="flex flex-col gap-4 p-5" aria-labelledby="account-appearance">
        <CardHeading id="account-appearance" title={t("account.appearance.title")} help={t("account.appearance.help")} />
        <div className="flex flex-col gap-1.5">
          <span id="account-theme" className="text-[13px] font-semibold">
            {t("account.appearance.theme")}
          </span>
          <Segmented
            labelId="account-theme"
            value={theme}
            onChange={(value) => {
              const next: Theme = value === "light" ? "light" : "dark";
              setTheme(next);
              setThemeState(next);
            }}
            options={[
              { value: "dark", label: t("account.appearance.dark") },
              { value: "light", label: t("account.appearance.light") },
            ]}
          />
        </div>
        <Field id="account-language" label={t("account.appearance.language")}>
          <select
            id="account-language"
            className={INPUT}
            value={language}
            onChange={() => {
              setLanguage("en");
              setLanguageState("en");
            }}
          >
            <option value="en">{t("account.appearance.english")}</option>
          </select>
        </Field>
      </Card>
    </div>
  );
}
