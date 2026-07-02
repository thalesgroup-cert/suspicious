import { z } from "zod";

export const artifactSchema = z.object({
  value: z
    .string()
    .trim()
    .min(1, "URL or indicator is required")
    .max(4096, "Input is too long"),
  context: z.string().optional(),
});

export const fileSchema = z.object({
  context: z.string().optional(),
});

export type ArtifactForm = z.infer<typeof artifactSchema>;
export type FileForm = z.infer<typeof fileSchema>;
