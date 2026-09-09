import * as React from "react";
import { Dialog, DialogContent, DialogTitle } from "@mui/material";

import { ScopePicker } from "@/features/home/components/ScopePicker";

/**
 * The "select your management scope" modal.
 *
 * Two modes:
 *  - forced (no `onClose`): shown to a CISO with no scope set yet, on Home and
 *    Investigation. No dismiss until a scope is confirmed.
 *  - editable (`onClose` given): reopened from the profile to narrow/widen an
 *    existing scope. Dismissible, pre-selects the current scope.
 *
 * The actual controls live in <ScopePicker>, also used inline on the profile
 * "Management scope" tab.
 */
export function CisoScopeDialog({
  open,
  onClose,
  currentScope,
  allowAll = false,
}: {
  open: boolean;
  onClose?: () => void;
  currentScope?: string;
  /** Show the "All cases" option (Admin group only). */
  allowAll?: boolean;
}) {
  return (
    <Dialog
      open={open}
      maxWidth="sm"
      fullWidth
      onClose={onClose ? () => onClose() : undefined}
    >
      <DialogTitle>Select your management scope</DialogTitle>
      <DialogContent>
        <ScopePicker
          key={open ? "open" : "closed"}
          enabled={open}
          currentScope={currentScope}
          allowAll={allowAll}
          onSaved={onClose}
          onCancel={onClose}
        />
      </DialogContent>
    </Dialog>
  );
}
