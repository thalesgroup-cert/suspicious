import * as React from "react";
import { Alert, Box, Button, Skeleton, TableCell, TableSortLabel } from "@mui/material";
import type { SortDir } from "@/features/campaigns/utils";

/**
 * One panel's own loading / error state, so a slow or failing query never blocks
 * the others. `what` completes "Could not load <what>." in plain words.
 */
export function PanelState<T>(props: {
  query: { data: T | undefined; isPending: boolean; isError: boolean; refetch: () => unknown };
  what: string;
  height?: number;
  children: (data: T) => React.ReactNode;
}) {
  const { query, what, height = 160 } = props;
  if (query.isError && query.data === undefined) {
    return (
      <Alert
        severity="error"
        action={
          <Button color="inherit" size="small" onClick={() => query.refetch()}>
            Retry
          </Button>
        }
      >
        Could not load {what}.
      </Alert>
    );
  }
  if (query.isPending || query.data === undefined) {
    return (
      <Box role="status" aria-label={`Loading ${what}`}>
        <Skeleton variant="rounded" height={height} />
      </Box>
    );
  }
  return <>{props.children(query.data)}</>;
}

/** Sortable header cell: TableCell's sortDirection sets aria-sort on the active column only. */
export function SortCell<K extends string>(props: {
  id: K;
  sort: { key: K; dir: SortDir };
  onSort: (key: K) => void;
  align?: "left" | "right";
  children: React.ReactNode;
}) {
  const active = props.sort.key === props.id;
  return (
    <TableCell align={props.align} sortDirection={active ? props.sort.dir : false}>
      <TableSortLabel active={active} direction={active ? props.sort.dir : "asc"} onClick={() => props.onSort(props.id)}>
        {props.children}
      </TableSortLabel>
    </TableCell>
  );
}
