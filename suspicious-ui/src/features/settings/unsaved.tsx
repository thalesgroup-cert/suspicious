// The provider and its hooks form one unit (one context), so they live together.
/* eslint-disable react-refresh/only-export-components */
import * as React from "react";
import { useBlocker } from "react-router";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";
import type { SectionKey } from "@/features/settings/components/sections";

type Ctx = { keys: ReadonlySet<SectionKey>; report(key: SectionKey, dirty: boolean): void };

const UnsavedContext = React.createContext<Ctx>({ keys: new Set(), report: () => undefined });

export function UnsavedProvider({ children }: React.PropsWithChildren) {
  const [keys, setKeys] = React.useState<ReadonlySet<SectionKey>>(new Set());

  const report = React.useCallback((key: SectionKey, dirty: boolean) => {
    setKeys((prev) => {
      if (prev.has(key) === dirty) return prev;
      const next = new Set(prev);
      if (dirty) next.add(key);
      else next.delete(key);
      return next;
    });
  }, []);

  const dirty = keys.size > 0;

  // Only while dirty: an always-on handler makes the browser nag on every close.
  React.useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [dirty]);

  // Switching section unmounts the panel and its draft, so it counts as leaving.
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) => dirty && currentLocation.pathname !== nextLocation.pathname,
  );

  const value = React.useMemo(() => ({ keys, report }), [keys, report]);

  return (
    <UnsavedContext.Provider value={value}>
      {children}
      <ConfirmDialog
        open={blocker.state === "blocked"}
        title="Discard unsaved changes?"
        body="Your edits have not been saved and will be lost if you leave."
        confirmLabel="Discard"
        destructive
        onConfirm={() => blocker.state === "blocked" && blocker.proceed()}
        onCancel={() => blocker.state === "blocked" && blocker.reset()}
      />
    </UnsavedContext.Provider>
  );
}

export function useReportUnsaved(key: SectionKey, dirty: boolean) {
  const { report } = React.useContext(UnsavedContext);
  React.useEffect(() => {
    report(key, dirty);
    return () => report(key, false);
  }, [report, key, dirty]);
}

export function useUnsavedKeys(): ReadonlySet<SectionKey> {
  return React.useContext(UnsavedContext).keys;
}
