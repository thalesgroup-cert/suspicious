import { z } from "zod";

const vendorSchema = z.object({
  name: z.string(),
  category: z.string(),
  result: z.string().nullable().optional(),
});

export const enrichmentSchema = z.object({
  source: z.string(),
  vendors: z.array(vendorSchema).optional(),
  malicious_count: z.number().optional(),
  suspicious_count: z.number().optional(),
  total: z.number().optional(),
  reputation: z.number().optional(),
  first_seen: z.string().optional(),
  last_seen: z.string().optional(),
  tags: z.array(z.string()).optional(),
  vt_link: z.string().optional(),
  as_owner: z.string().optional(),
  asn: z.number().optional(),
  country: z.string().optional(),
  continent: z.string().optional(),
  network: z.string().optional(),
  registrar: z.string().optional(),
  creation_date: z.string().optional(),
  categories: z.record(z.string(), z.string()).optional(),
  final_url: z.string().optional(),
  page_title: z.string().optional(),
  meaningful_name: z.string().optional(),
  names: z.array(z.string()).optional(),
  size: z.number().optional(),
  type_description: z.string().optional(),
  threat_category: z.string().optional(),
  threat_label: z.string().optional(),
});

export type Vendor = z.infer<typeof vendorSchema>;
export type Enrichment = z.infer<typeof enrichmentSchema>;

export function parseEnrichment(x: unknown): Enrichment | undefined {
  if (x === undefined || x === null) return undefined;
  const parsed = enrichmentSchema.safeParse(x);
  if (!parsed.success) {
    console.warn("enrichment payload failed validation", parsed.error.issues);
    return undefined;
  }
  return parsed.data;
}
