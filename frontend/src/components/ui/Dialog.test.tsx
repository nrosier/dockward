import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { Dialog } from "./Dialog";

describe("Dialog", () => {
  it("shows a close button and closes on Escape by default", async () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open onOpenChange={onOpenChange} title="Title">
        <p>Body</p>
      </Dialog>,
    );
    expect(screen.getByRole("button", { name: t("common.close") })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("with dismissible off hides the close button and ignores Escape and outside clicks", async () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open onOpenChange={onOpenChange} title="Title" dismissible={false}>
        <p>Body</p>
      </Dialog>,
    );
    expect(screen.queryByRole("button", { name: t("common.close") })).not.toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    fireEvent.pointerDown(document.body);
    fireEvent.click(document.body);
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});
