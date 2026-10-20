import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";

import { ConfirmDialog } from "@/features/settings/components/ConfirmDialog";
import { ConnectorDrawer } from "@/features/settings/components/ConnectorDrawer";
import { ConnectorGallery } from "@/features/settings/components/ConnectorGallery";
import { type Connector, listConnectors } from "@/features/settings/components/connectors";

/** The gallery, plus the drawer for the connector named by ?connector= (and ?tab=), so a link or a refresh reopens it. */
export function ConnectorsPanel() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["connectors"],
    queryFn: listConnectors,
  });
  const connectors = useMemo(() => data?.connectors ?? [], [data]);
  const [params, setParams] = useSearchParams();

  // An unknown name opens nothing.
  const selected = connectors.find((c) => c.name === params.get("connector")) ?? null;
  // The drawer slides out after the URL has lost the name, so it keeps the last connector until it has finished.
  const [held, setHeld] = useState<Connector | null>(null);
  if (selected && selected !== held) setHeld(selected);
  const shown = selected ?? held;

  const [dirty, setDirty] = useState(false);
  const onDirtyChange = useCallback((d: boolean) => setDirty(d), []);
  // Bumped on every open so a drawer that is still sliding out never hands its draft to the next one.
  const [opens, setOpens] = useState(0);
  // A deep link opens the drawer with no Configure button to hand focus back to, so on close focus goes to that connector's button.
  const [deepLinked, setDeepLinked] = useState(() => params.get("connector") !== null);
  // `from` is kept so the dialog title stays right while it fades out.
  const [pending, setPending] = useState<{ to: string; from: string; open: boolean } | null>(null);

  const setConnector = (name: string | null) => {
    const next = new URLSearchParams(params);
    if (name === null) next.delete("connector");
    else next.set("connector", name);
    // replace: opening or closing a drawer is not a page the Back button should walk through.
    setParams(next, { replace: true });
  };

  const configure = (name: string) => {
    setDeepLinked(false);
    if (selected && name !== selected.name && dirty) {
      setPending({ to: name, from: selected.name, open: true });
      return;
    }
    if (name !== selected?.name) setOpens((n) => n + 1);
    setConnector(name);
  };

  return (
    <>
      <ConnectorGallery
        connectors={connectors}
        loadErrors={data?.load_errors ?? {}}
        loading={isLoading}
        error={Boolean(error)}
        onRetry={() => void refetch()}
        onConfigure={configure}
      />
      {shown && (
        <ConnectorDrawer
          key={`${shown.name}:${opens}`}
          connector={shown}
          open={selected !== null}
          onClose={() => setConnector(null)}
          onExited={() => {
            if (deepLinked) {
              document.querySelector<HTMLElement>(`[data-configure="${CSS.escape(shown.name)}"]`)?.focus();
              setDeepLinked(false);
            }
            setHeld(null);
          }}
          onDirtyChange={onDirtyChange}
        />
      )}
      <ConfirmDialog
        open={pending?.open ?? false}
        title={`Discard unsaved changes to ${pending?.from}?`}
        body="Your edits to this connector have not been saved and will be lost."
        confirmLabel="Discard"
        destructive
        onConfirm={() => {
          if (pending) {
            setOpens((n) => n + 1);
            setConnector(pending.to);
          }
          setPending((p) => p && { ...p, open: false });
        }}
        onCancel={() => setPending((p) => p && { ...p, open: false })}
      />
    </>
  );
}
