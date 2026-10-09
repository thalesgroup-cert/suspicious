/** Binary units (1 KB = 1024 B), labelled KB/MB like the rest of the product. */
export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${Number(n.toFixed(1))} ${units[i]}`;
}
