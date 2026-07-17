import type { Step } from "react-joyride";

export const GLOBAL_STEPS: Step[] = [
  {
    target: '[data-tour="nav-primary"]',
    title: "Navigation",
    content: "Jump between the main sections of Suspicious from here.",
    placement: "right",
    skipBeacon: true,
  },
  {
    target: '[data-tour="nav-workspace"]',
    title: "Your workspace",
    content: "Investigations, campaigns, and alerts live in this group.",
    placement: "right",
  },
  {
    target: '[data-tour="user-card"]',
    title: "Your account",
    content: "Open your profile and appearance settings here.",
    placement: "right",
  },
  {
    target: '[data-tour="help"]',
    title: "Replay this tour",
    content: "Click Help any time to run this walkthrough again.",
    placement: "right",
  },
];

export const PAGE_STEPS: Record<string, Step[]> = {
  "/submit": [
    {
      target: '[data-tour="submit-form"]',
      title: "Submit something suspicious",
      content: "Drop an email, file, URL, IP, or hash here to start an analysis.",
      placement: "top",
    },
  ],
};

export function getStepsForPath(pathname: string): Step[] {
  const key = Object.keys(PAGE_STEPS)
    .filter((prefix) => pathname === prefix || pathname.startsWith(prefix + "/"))
    .sort((a, b) => b.length - a.length)[0];
  return key ? [...GLOBAL_STEPS, ...PAGE_STEPS[key]] : [...GLOBAL_STEPS];
}
