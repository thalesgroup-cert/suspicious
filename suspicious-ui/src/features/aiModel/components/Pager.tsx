import * as React from "react";
import { TablePagination } from "@mui/material";

export const PAGE = 10;

export function Pager({ count, offset, onChange, label }: { count: number; offset: number; onChange(o: number): void; label: string }) {
  // A resolve or a refresh can empty the page shown: step back one page (again on the next answer if needed).
  React.useEffect(() => {
    if (offset > 0 && offset >= count) onChange(Math.max(0, offset - PAGE));
  }, [offset, count, onChange]);
  return (
    <TablePagination
      component="div"
      count={count}
      page={Math.min(Math.floor(offset / PAGE), Math.max(0, Math.ceil(count / PAGE) - 1))}
      rowsPerPage={PAGE}
      rowsPerPageOptions={[]}
      onPageChange={(_, p) => onChange(p * PAGE)}
      slotProps={{ actions: { previousButton: { "aria-label": `Previous page of ${label}` }, nextButton: { "aria-label": `Next page of ${label}` } } }}
    />
  );
}
