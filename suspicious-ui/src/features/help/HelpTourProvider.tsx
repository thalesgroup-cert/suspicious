import * as React from "react";
import { useLocation } from "react-router-dom";
import { useJoyride } from "react-joyride";
import { getStepsForPath } from "./tourSteps";
import { HelpTourContext } from "./useHelpTour";

const SEEN_KEY = "suspicious.tour.seen";

export function HelpTourProvider({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const steps = React.useMemo(() => getStepsForPath(location.pathname), [location.pathname]);

  const { controls, Tour } = useJoyride({ continuous: true, steps });

  const start = React.useCallback(() => controls.start(), [controls]);

  // Auto-run once for first-time users. Runs on first mount only.
  const started = React.useRef(false);
  React.useEffect(() => {
    if (started.current) return;
    started.current = true;
    let seen = false;
    try { seen = localStorage.getItem(SEEN_KEY) === "1"; } catch { /* blocked */ }
    if (!seen) {
      try { localStorage.setItem(SEEN_KEY, "1"); } catch { /* blocked */ }
      controls.start();
    }
  }, [controls]);

  const value = React.useMemo(() => ({ start }), [start]);

  return (
    <HelpTourContext.Provider value={value}>
      {children}
      {Tour}
    </HelpTourContext.Provider>
  );
}
