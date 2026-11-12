import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { t } from "../../i18n";
import { json, stubApi, testQueryClient } from "../../test/render";
import type { ImagePlatform, SourceImage } from "../../types/sources";
import { ImagesTable } from "./ImagesTable";

function platform(id: string, name: string): ImagePlatform {
  return { id, platform: name, state: "stored", size_bytes: 1, pulled_at: 1_700_000_000, scans: [] };
}

const images: SourceImage[] = [
  { id: "i1", digest: "sha256:aa", tags: ["1.0.0", "latest"], platforms: [platform("p1", "linux/amd64"), platform("p2", "linux/arm64")] },
  { id: "i2", digest: "sha256:bb", tags: [], platforms: [platform("p3", "linux/amd64")] },
  { id: "i3", digest: "sha256:cc", tags: ["v/2 beta"], platforms: [platform("p4", "linux/amd64")] },
];

function setup(action?: (path: string) => Response | undefined) {
  const fetchMock = stubApi((path, init) => {
    if (path === "/api/v1/image-sources/s1/images") {
      return json({ items: images, page: 1, page_size: 200, total: 3 });
    }
    if (init?.method === "POST") return action?.(path);
    return undefined;
  });
  render(
    <QueryClientProvider client={testQueryClient()}>
      <ImagesTable sourceId="s1" />
    </QueryClientProvider>,
  );
  return fetchMock;
}

const posts = (fetchMock: ReturnType<typeof setup>) => fetchMock.mock.calls.filter((call) => call[1]?.method === "POST");

describe("tag actions on the images table", () => {
  it("renders_pull_and_scan_on_the_first_row_of_each_image", async () => {
    setup();
    expect(await screen.findByRole("button", { name: t("sources.tagActions.pull", { tag: "1.0.0" }) })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("sources.tagActions.scan", { tag: "1.0.0" }) })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("sources.tagActions.pull", { tag: "v/2 beta" }) })).toBeInTheDocument();
    // The second tag and the second platform row get none.
    expect(screen.queryByRole("button", { name: t("sources.tagActions.pull", { tag: "latest" }) })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(4);
  });

  it("rows_without_a_tag_have_no_buttons", async () => {
    setup();
    await screen.findByRole("table");
    const rows = screen.getAllByRole("row");
    // header + 2 + 1 + 1 body rows; the third body row is the untagged image.
    expect(rows).toHaveLength(5);
    expect(within(rows[3]).queryAllByRole("button")).toHaveLength(0);
  });

  it("pull_sends_one_post_for_one_tag", async () => {
    const fetchMock = setup(() => json({ queued: 1 }));
    await userEvent.click(await screen.findByRole("button", { name: t("sources.tagActions.pull", { tag: "v/2 beta" }) }));
    expect(await screen.findByText(t("sources.tagActions.queued"))).toBeInTheDocument();
    const calls = posts(fetchMock);
    expect(calls).toHaveLength(1);
    expect(String(calls[0][0])).toBe("/api/v1/image-sources/s1/tags/v%2F2%20beta/pull");
  });

  it("scan_sends_one_post_for_one_tag", async () => {
    const fetchMock = setup(() => json({ queued: 2 }));
    const button = await screen.findByRole("button", { name: t("sources.tagActions.scan", { tag: "1.0.0" }) });
    await userEvent.click(button);
    expect(await screen.findByText(t("sources.tagActions.queued"))).toBeInTheDocument();
    const calls = posts(fetchMock);
    expect(calls).toHaveLength(1);
    expect(String(calls[0][0])).toBe("/api/v1/image-sources/s1/tags/1.0.0/scan");
    expect(button).toHaveFocus();
  });

  it("shows_busy_on_409", async () => {
    setup(() => json({ error: { code: "conflict", message: "server text" } }, 409));
    await userEvent.click(await screen.findByRole("button", { name: t("sources.tagActions.pull", { tag: "1.0.0" }) }));
    expect(await screen.findByText(t("sources.tagActions.busy"))).toBeInTheDocument();
    expect(screen.queryByText("server text")).not.toBeInTheDocument();
  });

  it("shows_rate_limited_on_429", async () => {
    setup(
      () =>
        new Response(JSON.stringify({ error: { code: "rate_limited", message: "x" } }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "90" },
        }),
    );
    await userEvent.click(await screen.findByRole("button", { name: t("sources.tagActions.scan", { tag: "1.0.0" }) }));
    expect(await screen.findByText(t("sources.tagActions.rateLimitedWait", { time: "1:30" }))).toBeInTheDocument();
  });

  it("shows_rate_limited_without_a_wait_when_retry_after_is_missing", async () => {
    setup(() => json({ error: { code: "rate_limited", message: "x" } }, 429));
    await userEvent.click(await screen.findByRole("button", { name: t("sources.tagActions.scan", { tag: "1.0.0" }) }));
    expect(await screen.findByText(t("sources.tagActions.rateLimited"))).toBeInTheDocument();
  });

  it("shows_an_error_on_a_generic_failure", async () => {
    setup(() => json({ error: { code: "internal", message: "x" } }, 500));
    await userEvent.click(await screen.findByRole("button", { name: t("sources.tagActions.pull", { tag: "1.0.0" }) }));
    expect(await screen.findByText(t("sources.tagActions.failed"))).toBeInTheDocument();
  });
});
