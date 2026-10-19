import * as React from "react";
import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link } from "react-router";

import { renderWithProviders } from "@/test/utils";
import { UnsavedProvider, useReportUnsaved, useUnsavedKeys } from "../unsaved";

function Panel({ dirty }: { dirty: boolean }) {
  useReportUnsaved("scoring", dirty);
  const keys = useUnsavedKeys();
  return (
    <div>
      <output data-testid="keys">{[...keys].join(",")}</output>
      <Link to="/elsewhere">Leave</Link>
    </div>
  );
}

function setup(dirty: boolean) {
  return renderWithProviders(
    <UnsavedProvider>
      <Panel dirty={dirty} />
    </UnsavedProvider>,
    { routePath: "*", initialPath: "/here" },
  );
}

function fireBeforeUnload() {
  const ev = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(ev);
  return ev.defaultPrevented;
}

describe("unsaved", () => {
  it("reports the dirty key and clears it when the panel unmounts", async () => {
    const user = userEvent.setup();
    function Reader() {
      return <output data-testid="set">{[...useUnsavedKeys()].join(",")}</output>;
    }
    function Dirty() {
      useReportUnsaved("scoring", true);
      return null;
    }
    function Host() {
      const [shown, setShown] = React.useState(true);
      return (
        <UnsavedProvider>
          <Reader />
          {shown && <Dirty />}
          <button onClick={() => setShown(false)}>Hide panel</button>
        </UnsavedProvider>
      );
    }
    renderWithProviders(<Host />, { routePath: "*", initialPath: "/here" });
    await waitFor(() => expect(screen.getByTestId("set")).toHaveTextContent("scoring"));
    await user.click(screen.getByRole("button", { name: "Hide panel" }));
    await waitFor(() => expect(screen.getByTestId("set")).toBeEmptyDOMElement());
  });

  it("only guards beforeunload while something is dirty", async () => {
    const clean = setup(false);
    expect(fireBeforeUnload()).toBe(false);
    clean.unmount();
    const dirty = setup(true);
    await waitFor(() => expect(fireBeforeUnload()).toBe(true));
    dirty.unmount();
    expect(fireBeforeUnload()).toBe(false);
  });

  it("prompts on navigation and stays when cancelled", async () => {
    const user = userEvent.setup();
    const { router } = setup(true);
    await waitFor(() => expect(screen.getByTestId("keys")).toHaveTextContent("scoring"));
    await user.click(screen.getByRole("link", { name: "Leave" }));
    expect(await screen.findByRole("dialog", { name: "Discard unsaved changes?" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(router!.state.location.pathname).toBe("/here");
  });

  it("proceeds when the user discards", async () => {
    const user = userEvent.setup();
    const { router } = setup(true);
    await waitFor(() => expect(screen.getByTestId("keys")).toHaveTextContent("scoring"));
    await user.click(screen.getByRole("link", { name: "Leave" }));
    await user.click(await screen.findByRole("button", { name: "Discard" }));
    await waitFor(() => expect(router!.state.location.pathname).toBe("/elsewhere"));
  });

  it("does not prompt when clean", async () => {
    const user = userEvent.setup();
    const { router } = setup(false);
    await user.click(screen.getByRole("link", { name: "Leave" }));
    await waitFor(() => expect(router!.state.location.pathname).toBe("/elsewhere"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
