import { describe, expect, it } from "vitest";
import { t } from "../../i18n";
import { triggerLabel } from "./labels";

describe("triggerLabel", () => {
  it("trigger_label_is_never_none", () => {
    for (const absent of [null, undefined, "", "  "]) {
      const label = triggerLabel(absent);
      expect(label).toBe(t("jobs.trigger.scheduled"));
      expect(label).toBe("Scheduled");
      expect(label.trim()).not.toBe("");
      expect(label).not.toBe("None");
    }
    expect(triggerLabel("scheduled")).toBe("Scheduled");
    expect(triggerLabel("manual")).toBe(t("jobs.trigger.manual"));
  });
});
