import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { json, renderAt, stubApi, user } from "../../test/render";
import { Topbar } from "./Topbar";

function stub(about: () => Response) {
  return stubApi((path) => {
    if (path === "/api/v1/account/me") {
      return json({ user: user("user") });
    }
    if (path === "/api/v1/about") {
      return about();
    }
    return undefined;
  });
}

const licenceText = () => (screen.getByLabelText("Licence text") as HTMLTextAreaElement).value;

const OPEN = { name: /^v/ };

describe("About dialog", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("opens from the header version, shows versions and licences, and Escape closes it", async () => {
    const fetchMock = stub(() => json({ dockward: "0.8.0", trivy: "v0.76.2", grype: null }));
    renderAt(<Topbar onMenu={() => {}} />);
    const button = screen.getByRole("button", OPEN);
    // Nothing is fetched until the dialog opens.
    expect(fetchMock.mock.calls.map((call) => String(call[0]))).not.toContain("/api/v1/about");
    await userEvent.click(button);
    const dialog = await screen.findByRole("dialog", { name: "About dockward" });
    expect(await screen.findByText("v0.76.2")).toBeInTheDocument();
    expect(screen.getByRole("rowheader", { name: "Trivy (bundled)" })).toBeInTheDocument();
    expect(screen.getByRole("rowheader", { name: "Grype (bundled)" })).toBeInTheDocument();
    // A failed read shows "unknown".
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(dialog).toHaveTextContent("Version 0.8.0 · MIT License");
    for (const name of ["dockward", "Trivy", "Grype"]) {
      expect(screen.getByRole("button", { name: `Full text of the ${name} licence` })).toBeInTheDocument();
    }
    // MIT text first, then the Apache text on request.
    expect(licenceText()).toContain("Permission is hereby granted");
    await userEvent.click(screen.getByRole("button", { name: "Full text of the Trivy licence" }));
    expect(licenceText()).toContain("Apache License");
    expect(licenceText()).toContain("Aqua Security");
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(button).toHaveFocus());
  });

  it("closes with the Close button", async () => {
    stub(() => json({ dockward: "0.8.0", trivy: "v0.76.2", grype: "v0.121.3" }));
    renderAt(<Topbar onMenu={() => {}} />);
    await userEvent.click(screen.getByRole("button", OPEN));
    expect(await screen.findByText("v0.121.3")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Close" })[0]);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("says so when the route fails", async () => {
    stub(() => json({ error: { code: "internal", message: "x" } }, 500));
    renderAt(<Topbar onMenu={() => {}} />);
    await userEvent.click(screen.getByRole("button", OPEN));
    expect(await screen.findByRole("alert")).toHaveTextContent("The versions could not be loaded.");
  });
});
