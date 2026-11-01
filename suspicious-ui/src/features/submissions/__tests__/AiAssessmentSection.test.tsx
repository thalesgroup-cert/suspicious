import { render, screen } from "@testing-library/react";
import { test, expect } from "vitest";
import { AiAssessmentSection } from "../components/AiAssessmentSection";
import type { AiAssessment } from "../api";

const base: AiAssessment = {
  result: "Dangerous",
  sub_class: "CREDENTIAL_PHISHING",
  tier: "high",
  runner_up: null,
  model_version: "v1",
  analysed_at: "2026-10-31T10:00:00Z",
  reads: "body only",
  similar_cases: [],
  campaign: null,
  cross_check: { facts: [], disagrees: false },
};

test("high tier shows chip and meaning", () => {
  render(<AiAssessmentSection assessment={base} />);
  expect(screen.getByText("High")).toBeInTheDocument();
  expect(screen.getByText("The model is confident")).toBeInTheDocument();
  expect(screen.getByText(/body only/)).toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/%|\d\.\d/);
});

test("low tier shows runner-up", () => {
  render(<AiAssessmentSection assessment={{ ...base, tier: "low", runner_up: { result: "Safe" } }} />);
  expect(screen.getByText("Low")).toBeInTheDocument();
  expect(screen.getByText("Runner-up: Safe")).toBeInTheDocument();
  expect(screen.getByText("The model is unsure, rely on the other evidence")).toBeInTheDocument();
});

test("no tier says not calibrated", () => {
  render(<AiAssessmentSection assessment={{ ...base, tier: "" }} />);
  expect(screen.getByText("Confidence not calibrated")).toBeInTheDocument();
  expect(screen.queryByText("High")).not.toBeInTheDocument();
});

test("similar cases table and none", () => {
  const { rerender } = render(
    <AiAssessmentSection
      assessment={{
        ...base,
        similar_cases: [
          { case_id: 12, similarity: 0.91, label: "Dangerous", provenance: "analyst" },
          { case_id: 13, similarity: null, label: null, provenance: null },
        ],
      }}
    />,
  );
  expect(screen.getAllByRole("row")).toHaveLength(3);
  expect(screen.getByText("analyst")).toBeInTheDocument();
  expect(document.body.textContent).not.toContain("0.91");
  rerender(<AiAssessmentSection assessment={base} />);
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

test("campaign line and disagreement", () => {
  render(
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
  expect(screen.getByText("Decisive rule: deny-listed")).toBeInTheDocument();
});
