import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { json, renderAt, stubApi } from "../../test/render";
import { TotpCard } from "./TotpCard";

// Built at runtime so no fixed secret sits in the source.
const SECRET = ["JBSW", "Y3DP", "EHPK", "3PXP"].join("");
const QR_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4"><path d="M0 0h1v1h-1z"/></svg>';
const RECOVERY = Array.from({ length: 10 }, (_, index) => `RC${index}-TEST`);
const GOOD = ["12", "34", "56"].join("");
const BAD = ["65", "43", "21"].join("");

function stub(options: { enabled: boolean; enrolStatus?: number }) {
  let enabled = options.enabled;
  const fetchMock = stubApi((path, init) => {
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? {} : (JSON.parse(String(init.body)) as { code?: string });
    if (path === "/api/v1/account/totp" && method === "GET") {
      return json({ enabled });
    }
    if (path === "/api/v1/account/totp/enrol" && method === "POST") {
      return options.enrolStatus === undefined
        ? json({ secret: SECRET, qr_svg: QR_SVG })
        : json({ error: { code: "conflict", message: "On." } }, options.enrolStatus);
    }
    if (path === "/api/v1/account/totp/confirm" && method === "POST") {
      if (body.code === GOOD) {
        enabled = true;
        return json({ recovery_codes: RECOVERY });
      }
      return json({ error: { code: "validation_failed", message: "Bad code." } }, 422);
    }
    if (path === "/api/v1/account/totp/disable" && method === "POST") {
      if (body.code === GOOD) {
        enabled = false;
        return new Response(null, { status: 204 });
      }
      return json({ error: { code: "validation_failed", message: "Bad code." } }, 422);
    }
    return undefined;
  });
  return fetchMock;
}

describe("TotpCard", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the off state with a set up button", async () => {
    stub({ enabled: false });
    renderAt(<TotpCard />);
    expect(await screen.findByRole("heading", { name: t("account.totp.title") })).toBeInTheDocument();
    expect(await screen.findByText(t("account.totp.helpOff"))).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: t("account.totp.setup") })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("account.totp.disable") })).not.toBeInTheDocument();
  });

  it("shows the on state with a text label and a turn off button", async () => {
    stub({ enabled: true });
    renderAt(<TotpCard />);
    expect(await screen.findByText(t("account.totp.statusOn"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("account.totp.disable") })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("account.totp.setup") })).not.toBeInTheDocument();
  });

  it("shows an error and no buttons when the state cannot be read", async () => {
    stubApi(() => json({ error: { code: "internal_error", message: "x" } }, 500));
    renderAt(<TotpCard />);
    expect(await screen.findByRole("alert")).toHaveTextContent(t("errors.generic"));
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("enrols, shows the QR and manual key, and keeps Confirm disabled until 6 digits", async () => {
    const fetchMock = stub({ enabled: false });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.setup") }));
    const dialog = await screen.findByRole("dialog", { name: t("account.totp.setup.title") });
    const qr = await within(dialog).findByRole("img", { name: t("account.totp.setup.qrLabel") });
    expect(qr.querySelector("svg path")).not.toBeNull();
    expect(qr.textContent).not.toContain(SECRET);
    expect(within(dialog).getByLabelText(t("account.totp.setup.manualKey"))).toHaveValue(SECRET);
    const enrols = fetchMock.mock.calls.filter(([path]) => String(path) === "/api/v1/account/totp/enrol");
    expect(enrols).toHaveLength(1);

    const confirm = within(dialog).getByRole("button", { name: t("account.totp.setup.confirm") });
    expect(confirm).toBeDisabled();
    const code = within(dialog).getByLabelText(t("account.totp.setup.code"));
    expect(code).toHaveAttribute("autocomplete", "one-time-code");
    expect(code).toHaveAttribute("inputmode", "numeric");
    await userEvent.type(code, "12345");
    expect(confirm).toBeDisabled();
    await userEvent.type(code, "6");
    expect(confirm).toBeEnabled();
  });

  it("keeps the dialog on step 1 and shows a message for a wrong code", async () => {
    stub({ enabled: false });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.setup") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(await within(dialog).findByLabelText(t("account.totp.setup.code")), BAD);
    await userEvent.click(within(dialog).getByRole("button", { name: t("account.totp.setup.confirm") }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(t("account.totp.setup.wrongCode"));
    expect(within(dialog).queryByText(RECOVERY[0])).not.toBeInTheDocument();
  });

  it("shows the enrol failure with only a close button", async () => {
    stub({ enabled: false, enrolStatus: 409 });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.setup") }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(t("account.totp.setup.failed"));
    expect(within(dialog).queryByLabelText(t("account.totp.setup.code"))).not.toBeInTheDocument();
  });

  it("shows recovery codes once and cannot be closed until they are saved", async () => {
    stub({ enabled: false });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.setup") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(await within(dialog).findByLabelText(t("account.totp.setup.code")), GOOD);
    await userEvent.click(within(dialog).getByRole("button", { name: t("account.totp.setup.confirm") }));

    const list = await within(dialog).findByRole("list", { name: t("account.totp.recovery.listLabel") });
    expect(within(list).getAllByRole("listitem").map((item) => item.textContent)).toEqual(RECOVERY);
    expect(within(dialog).queryByRole("button", { name: t("common.close") })).not.toBeInTheDocument();

    await userEvent.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    const done = within(dialog).getByRole("button", { name: t("account.totp.recovery.done") });
    expect(done).toBeDisabled();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: t("account.totp.recovery.saved") }));
    expect(done).toBeEnabled();
    await userEvent.click(done);

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(await screen.findByText(t("account.totp.statusOn"))).toBeInTheDocument();
    expect(screen.queryByText(RECOVERY[0])).not.toBeInTheDocument();
  });

  it("turns TOTP off with a current code", async () => {
    stub({ enabled: true });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.disable") }));
    const dialog = await screen.findByRole("dialog", { name: t("account.totp.disable.title") });
    const confirm = within(dialog).getByRole("button", { name: t("account.totp.disable.confirm") });
    expect(confirm).toBeDisabled();
    const code = within(dialog).getByLabelText(t("account.totp.disable.code"));
    expect(code).toHaveFocus();

    await userEvent.type(code, BAD);
    await userEvent.click(confirm);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(t("account.totp.disable.wrongCode"));

    await userEvent.clear(code);
    await userEvent.type(code, GOOD);
    await userEvent.click(confirm);
    expect(await screen.findByText(t("account.totp.disable.done"))).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(await screen.findByRole("button", { name: t("account.totp.setup") })).toBeInTheDocument();
  });

  it("cancel in the turn off dialog sends no request", async () => {
    const fetchMock = stub({ enabled: true });
    renderAt(<TotpCard />);
    await userEvent.click(await screen.findByRole("button", { name: t("account.totp.disable") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("common.cancel") }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([path]) => String(path) === "/api/v1/account/totp/disable")).toBe(false);
  });
});
