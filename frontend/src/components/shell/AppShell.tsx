import * as RadixDialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { Outlet } from "react-router";
import { t } from "../../i18n";
import { getRailCollapsed, setRailCollapsed } from "../../lib/preferences";
import { Rail } from "./Rail";
import { Topbar } from "./Topbar";

// Rail, sticky header, and the page content capped at 64rem. Below `md` the
// rail moves into a drawer behind the header's menu button.
export function AppShell() {
  const [collapsed, setCollapsed] = useState(getRailCollapsed);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    setRailCollapsed(next);
  };

  return (
    <div className="flex min-h-screen bg-bg text-text">
      <aside
        className={`hidden shrink-0 border-r border-border bg-surface md:block ${collapsed ? "w-[72px]" : "w-[232px]"}`}
      >
        <div className="sticky top-0 h-screen overflow-y-auto">
          <Rail collapsed={collapsed} onToggle={toggle} />
        </div>
      </aside>

      <RadixDialog.Root open={drawerOpen} onOpenChange={setDrawerOpen}>
        <RadixDialog.Portal>
          <RadixDialog.Overlay className="fixed inset-0 z-40 bg-black/60 md:hidden" />
          <RadixDialog.Content
            aria-describedby={undefined}
            className="fixed inset-y-0 left-0 z-50 w-[260px] max-w-[85vw] overflow-y-auto border-r border-border bg-surface md:hidden"
          >
            <RadixDialog.Title className="sr-only">{t("rail.label")}</RadixDialog.Title>
            <Rail collapsed={false} onToggle={toggle} onNavigate={() => setDrawerOpen(false)} inDrawer />
          </RadixDialog.Content>
        </RadixDialog.Portal>
      </RadixDialog.Root>

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setDrawerOpen(true)} />
        <main className="px-4 pt-7 pb-14 md:px-8">
          <div className="mx-auto flex max-w-[64rem] flex-col gap-7">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
