import * as React from "react";
import { useLocation } from "react-router-dom";
import { useJoyride } from "react-joyride";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getProfile, updatePreferences, type UserProfile } from "@/features/profile/api";
import { getStepsForPath } from "./tourSteps";
import { HelpTourContext } from "./useHelpTour";

export function HelpTourProvider({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const steps = React.useMemo(() => getStepsForPath(location.pathname), [location.pathname]);
  const queryClient = useQueryClient();

  const { controls, Tour } = useJoyride({ continuous: true, steps });

  const start = React.useCallback(() => controls.start(), [controls]);

  // The "seen once" flag lives on the profile (tour_completed) so it is
  // per-user and follows the account across devices — unlike localStorage.
  const profileQuery = useQuery({ queryKey: ["profile"], queryFn: getProfile, retry: false });

  const markSeen = React.useCallback(() => {
    queryClient.setQueryData<UserProfile>(["profile"], (prev) =>
      prev ? { ...prev, tour_completed: true } : prev,
    );
    // Fire-and-forget: the tour is idempotent, so a failed PATCH just means
    // it may auto-run again next session — no error surfaced to the user.
    updatePreferences({ tour_completed: true }).catch(() => {});
  }, [queryClient]);

  // Auto-run once for first-time users, after the profile has loaded.
  const started = React.useRef(false);
  React.useEffect(() => {
    if (started.current || !profileQuery.isSuccess) return;
    started.current = true;
    if (!profileQuery.data.tour_completed) {
      markSeen();
      controls.start();
    }
  }, [profileQuery.isSuccess, profileQuery.data, controls, markSeen]);

  const value = React.useMemo(() => ({ start }), [start]);

  return (
    <HelpTourContext.Provider value={value}>
      {children}
      {Tour}
    </HelpTourContext.Provider>
  );
}
