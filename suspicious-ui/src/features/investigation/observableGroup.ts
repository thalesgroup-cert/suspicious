import { z } from "zod";

const sourceSchema = z.object({
  name: z.string(),
  tier: z.number(),
  // Backend (Task 9) guarantees "malicious"|"suspicious"|"clean"|"no-data";
  // kept as string so callers can pass plain fixtures without a cast.
  verdict: z.string(),
  confidence: z.number().nullable(),
  evidence: z.string(),
  failed: z.boolean(),
  report_full: z.unknown(),
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
});

export const observableGroupSchema = z.object({
  observables: z.array(observableSchema),
});

export type Source = z.infer<typeof sourceSchema>;
export type Observable = z.infer<typeof observableSchema>;
export type ObservableGroup = z.infer<typeof observableGroupSchema>;

export function parseObservableGroup(x: unknown): ObservableGroup | undefined {
  const parsed = observableGroupSchema.safeParse(x);
  return parsed.success ? parsed.data : undefined;
}
