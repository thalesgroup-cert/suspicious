import { describe, it, expect } from "vitest";
import { GLOBAL_STEPS, getStepsForPath } from "../tourSteps";

describe("getStepsForPath", () => {
  it("returns only the global steps for an unknown route", () => {
    expect(getStepsForPath("/nope")).toEqual(GLOBAL_STEPS);
  });

  it("appends page steps for a matching route prefix", () => {
    const steps = getStepsForPath("/submit/new");
    expect(steps.length).toBeGreaterThan(GLOBAL_STEPS.length);
    // global steps come first
    expect(steps.slice(0, GLOBAL_STEPS.length)).toEqual(GLOBAL_STEPS);
  });

  it("picks the longest matching prefix", () => {
    // "/submit" is a prefix of "/submit/new"; ensure it matches, not "/"
    const steps = getStepsForPath("/submit");
    expect(steps.some((s) => s.target === '[data-tour="submit-form"]')).toBe(true);
  });
});
