import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Button } from "@mui/material";

import { renderWithProviders } from "@/test/utils";
import { ConfirmDialog } from "../ConfirmDialog";

function Harness({
  destructive,
  onConfirm,
  onCancel,
}: {
  destructive?: boolean;
  onConfirm: () => void;
  onCancel?: () => void;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Open</Button>
      <ConfirmDialog
        open={open}
        title="Delete 3 entries?"
        body="This cannot be undone."
        confirmLabel="Delete"
        destructive={destructive}
        onConfirm={() => {
          setOpen(false);
          onConfirm();
        }}
        onCancel={() => {
          setOpen(false);
          onCancel?.();
        }}
      />
    </>
  );
}

describe("ConfirmDialog", () => {
  it("is a named, described dialog and focuses Cancel when destructive", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Harness destructive onConfirm={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete 3 entries?" });
    expect(dialog).toHaveAccessibleDescription("This cannot be undone.");
    expect(within(dialog).queryAllByRole("heading")).toHaveLength(0);
    await waitFor(() => expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus());
  });

  it("Escape cancels without confirming and returns focus to the opener", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    renderWithProviders(<Harness destructive onConfirm={onConfirm} onCancel={onCancel} />);
    const opener = screen.getByRole("button", { name: "Open" });
    await user.click(opener);
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it("calls onConfirm exactly once", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    renderWithProviders(<Harness onConfirm={onConfirm} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
