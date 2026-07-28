import * as React from "react";
import { useLocation } from "react-router";
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

  const profileQuery = useQuery({ queryKey: ["profile"], queryFn: getProfile, retry: false });

  const markSeen = React.useCallback(() => {
    queryClient.setQueryData<UserProfile>(["profile"], (prev) =>
      prev ? { ...prev, tour_completed: true } : prev,
    );
    updatePreferences({ tour_completed: true }).catch(() => {});
  }, [queryClient]);

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
