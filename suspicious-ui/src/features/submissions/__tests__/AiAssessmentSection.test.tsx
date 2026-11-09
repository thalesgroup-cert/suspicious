import { render, screen } from "@testing-library/react";
import { test, expect } from "vitest";
import { AiAssessmentSection } from "../components/AiAssessmentSection";
import type { AiAssessment } from "../api";

const base: AiAssessment = {
  result: "Dangerous",
  sub_class: "CREDENTIAL_PHISHING",
  tier: "high",
  runner_up: { result: "Safe" },
  model_version: "v1.2",
  analysed_at: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
  reads: "body only",
  similar_cases: [{ case_id: 12, similarity: 0.91, label: "Dangerous", provenance: "analyst" }],
  campaign: null,
  cross_check: { facts: [], disagrees: false },
};

const MEANINGS = [
  "The model is confident",
  "The model leans this way, check the evidence",
  "The model is unsure, rely on the other evidence",
];

test("renders heading, humanised class, version and age", () => {
  render(<AiAssessmentSection assessment={base} />);
  expect(screen.getByRole("heading", { name: "AI model assessment" })).toBeInTheDocument();
  expect(screen.getByText("Credential phishing")).toBeInTheDocument();
  expect(screen.getByText(/Model v1\.2, analysed 3 h ago/)).toBeInTheDocument();
  expect(screen.getByText(/body only/)).toBeInTheDocument();
});

test.each([
  ["high", "High", MEANINGS[0]],
  ["medium", "Medium", MEANINGS[1]],
  ["low", "Low", MEANINGS[2]],
] as const)("tier %s shows its chip and only its meaning", (tier, chip, meaning) => {
  render(<AiAssessmentSection assessment={{ ...base, tier }} />);
  expect(screen.getByText(chip)).toBeInTheDocument();
  expect(screen.getByText(meaning)).toBeInTheDocument();
  for (const m of MEANINGS.filter((x) => x !== meaning)) expect(screen.queryByText(m)).not.toBeInTheDocument();
});

test("runner-up only on low tier", () => {
  const { rerender } = render(<AiAssessmentSection assessment={{ ...base, tier: "low" }} />);
  expect(screen.getByText("Runner-up: Safe")).toBeInTheDocument();
  for (const tier of ["high", "medium", ""] as const) {
    rerender(<AiAssessmentSection assessment={{ ...base, tier }} />);
    expect(screen.queryByText(/Runner-up/)).not.toBeInTheDocument();
  }
});

test("empty tier says not calibrated, no chip, no meaning", () => {
  render(<AiAssessmentSection assessment={{ ...base, tier: "" }} />);
  expect(screen.getByText("Confidence not calibrated")).toBeInTheDocument();
  for (const t of ["High", "Medium", "Low"]) expect(screen.queryByText(t)).not.toBeInTheDocument();
  for (const m of MEANINGS) expect(screen.queryByText(m)).not.toBeInTheDocument();
});

test("similar cases: null members show a dash, never 'null'", () => {
  const { container, rerender } = render(
    <AiAssessmentSection
      assessment={{
        ...base,
        similar_cases: [
          { case_id: 12, similarity: 0.91, label: "Dangerous", provenance: "analyst" },
          { case_id: null, similarity: null, label: null, provenance: null },
        ],
      }}
    />,
  );
  expect(screen.getByRole("table", { name: "Similar cases" })).toBeInTheDocument();
  expect(screen.getAllByRole("row")).toHaveLength(3);
  expect(screen.getByText("analyst")).toBeInTheDocument();
  expect(container.textContent).not.toContain("null");
  expect(screen.getAllByText("—")).toHaveLength(3);
  rerender(<AiAssessmentSection assessment={{ ...base, similar_cases: [] }} />);
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

test("no percent and no similarity value in any state", () => {
  for (const tier of ["high", "medium", "low", ""] as const) {
    const { container, unmount } = render(
      <AiAssessmentSection
        assessment={{
          ...base,
          tier,
          similar_cases: [{ case_id: 12, similarity: 0.91, label: "Dangerous", provenance: "analyst" }],
        }}
      />,
    );
    expect(container.textContent).not.toContain("%");
    expect(container.textContent).not.toContain("0.91");
    expect(container.textContent).not.toContain("91");
    unmount();
  }
});

test("campaign line pluralises; disagreement and facts list", () => {
  const { rerender } = render(
    <AiAssessmentSection
      assessment={{
        ...base,
        campaign: { ref: "261031-865a1", size: 9 },
        cross_check: { facts: [{ kind: "rule", text: "Decisive rule: deny-listed" }], disagrees: true },
      }}
    />,
  );
  expect(screen.getByText("Campaign 261031-865a1, 9 mails")).toBeInTheDocument();
  expect(screen.getByText("AI disagrees with the evidence")).toBeInTheDocument();
  expect(screen.getByRole("listitem")).toHaveTextContent("Decisive rule: deny-listed");
  rerender(<AiAssessmentSection assessment={{ ...base, campaign: { ref: "r", size: 1 } }} />);
  expect(screen.getByText("Campaign r, 1 mail")).toBeInTheDocument();
});

test.each([[""], ["not a date"]])("omits the age when analysed_at is %j", (analysed_at) => {
  const { container } = render(<AiAssessmentSection assessment={{ ...base, analysed_at }} />);
  expect(screen.getByText(/Model v1\.2\./)).toBeInTheDocument();
  expect(container.textContent).not.toContain("analysed");
  expect(container.textContent).not.toContain("not checked yet");
});

test("omits the cross-check block when cross_check is null", () => {
  render(<AiAssessmentSection assessment={{ ...base, cross_check: null }} />);
  expect(screen.getByRole("heading", { name: "AI model assessment" })).toBeInTheDocument();
  expect(screen.queryByRole("listitem")).toBeNull();
  expect(screen.queryByText("AI disagrees with the evidence")).toBeNull();
});
