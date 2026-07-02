import { createContext, useContext } from "react";

export interface HelpTourValue {
  start: () => void;
}

export const HelpTourContext = createContext<HelpTourValue | null>(null);

export function useHelpTour(): HelpTourValue {
  const ctx = useContext(HelpTourContext);
  if (!ctx) throw new Error("useHelpTour must be used within a HelpTourProvider");
  return ctx;
}
