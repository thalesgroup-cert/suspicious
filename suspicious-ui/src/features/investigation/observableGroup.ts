import { z } from "zod";

import { enrichmentSchema } from "./enrichment";

const sourceSchema = z.object({
  name: z.string(),
  tier: z.number(),
  // Backend (Task 9) guarantees "malicious"|"suspicious"|"clean"|"no-data";
  // kept as string so callers can pass plain fixtures without a cast.
  verdict: z.string(),
  confidence: z.number().nullable(),
  evidence: z.string(),
  failed: z.boolean(),
  report: z.unknown(),
  enrichment: enrichmentSchema.nullable().optional().catch(undefined),
});

const observableSchema = z.object({
  value: z.string(),
  type: z.string(),
  verdict: z
    .object({
      band: z.string(),
      confidence: z.number(),
      rationale: z.array(z.string()),
    })
    .nullable(),
  sources: z.array(sourceSchema),
  derived_from: z
    .object({
      value: z.string(),
      via_analyzer: z.string(),
    })
    .nullable()
    .optional(),
  escalation_note: z.string().optional(),
  screenshot_url: z.string().nullable().optional(),
});

export const observableGroupSchema = z.object({
  observables: z.array(observableSchema),
});

export type Source = z.infer<typeof sourceSchema>;
export type Observable = z.infer<typeof observableSchema>;
export type ObservableGroup = z.infer<typeof observableGroupSchema>;

export function parseObservableGroup(x: unknown): ObservableGroup | undefined {
  if (x === undefined || x === null) return undefined;
  const parsed = observableGroupSchema.safeParse(x);
  if (!parsed.success) {
    // A present-but-unparseable payload means the backend shape drifted;
    // the page will silently fall back to the legacy layout without this.
    console.warn("observable_group payload failed validation", parsed.error.issues);
    return undefined;
  }
  return parsed.data;
}
