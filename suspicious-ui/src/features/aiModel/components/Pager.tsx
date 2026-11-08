import { TablePagination } from "@mui/material";

export const PAGE = 10;

export function Pager({ count, offset, onChange, label }: { count: number; offset: number; onChange(o: number): void; label: string }) {
  return (
    <TablePagination
      component="div"
      count={count}
      page={Math.floor(offset / PAGE)}
      rowsPerPage={PAGE}
      rowsPerPageOptions={[]}
      onPageChange={(_, p) => onChange(p * PAGE)}
      slotProps={{ actions: { previousButton: { "aria-label": `Previous page of ${label}` }, nextButton: { "aria-label": `Next page of ${label}` } } }}
    />
  );
}
