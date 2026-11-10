import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../i18n";
import { json, renderAt, stubApi } from "../test/render";
import AdminBackupPage from "./AdminBackupPage";

describe("AdminBackupPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the written file path", async () => {
    stubApi((path, init) =>
      path === "/api/v1/admin/backup" && init?.method === "POST"
        ? json({ file: "harborgate-20261103T140512Z.hgbk", path: "/data/backups" }, 201)
        : undefined,
    );
    renderAt(<AdminBackupPage />, "/admin/settings/backup");
    await userEvent.click(screen.getByRole("button", { name: t("admin.backup.create") }));
    expect(await screen.findByText(t("admin.backup.written"))).toBeInTheDocument();
    const path = "/data/backups/harborgate-20261103T140512Z.hgbk";
    expect(screen.getByText(path)).toBeInTheDocument();
    expect(screen.getByText(`dockward restore ${path}`)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /restore/i })).toBeNull();
  });

  it("explains a failed backup", async () => {
    stubApi(() => json({ error: { code: "internal_error", message: "x" } }, 500));
    renderAt(<AdminBackupPage />, "/admin/settings/backup");
    await userEvent.click(screen.getByRole("button", { name: t("admin.backup.create") }));
    expect(await screen.findByText(t("admin.backup.failed"))).toBeInTheDocument();
  });
});
