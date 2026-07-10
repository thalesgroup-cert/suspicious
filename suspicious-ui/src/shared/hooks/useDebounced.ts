
import * as React from "react";

export function useDebounced<T>(value: T, delayMs = 200) {
  const [v, setV] = React.useState(value);

  React.useEffect(() => {
    const t = window.setTimeout(() => setV(value), delayMs);
    return () => window.clearTimeout(t);
  }, [value, delayMs]);

  return v;
}
