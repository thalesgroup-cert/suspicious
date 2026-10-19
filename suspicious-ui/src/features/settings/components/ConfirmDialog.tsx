import * as React from "react";
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle } from "@mui/material";

export type ConfirmDialogProps = {
  open: boolean;
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  onConfirm(): void;
  onCancel(): void;
};

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  destructive = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const id = React.useId();
  return (
    <Dialog open={open} onClose={onCancel} aria-labelledby={`${id}-title`} aria-describedby={`${id}-body`}>
      <DialogTitle id={`${id}-title`}>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText id={`${id}-body`} component="div">
          {body}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        {/* Destructive dialogs start on Cancel so a stray Enter cannot delete. */}
        <Button onClick={onCancel} autoFocus={destructive}>
          Cancel
        </Button>
        <Button
          onClick={onConfirm}
          variant="contained"
          color={destructive ? "error" : "primary"}
          autoFocus={!destructive}
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
