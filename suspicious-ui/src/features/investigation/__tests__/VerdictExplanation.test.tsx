import { render, screen } from "@testing-library/react";
import { fireEvent } from "@testing-library/react";
import { test, expect } from "vitest";
import { VerdictExplanation } from "../VerdictExplanation";
import type { VerdictExplanationDTO } from "../api";

const data: VerdictExplanationDTO = {
  band: "dangerous",
  confidence: 0.82,
  decisive_rule: "tier-1 malicious",
  analyst_paragraph: "The domain resolves to a known phishing kit host.",
  reporter_paragraph: "This link is unsafe.",
  confidence_reading: "High confidence — 3 of 4 sources agree.",
  sources: [
    { name: "virustotal", tier: 1, verdict: "malicious", counted: true, note: "12/70 vendors" },
    { name: "urlscan", tier: 2, verdict: "suspicious", counted: false, note: "below threshold" },
  ],
};

test("renders the analyst paragraph and confidence reading", () => {
  render(<VerdictExplanation data={data} />);
  expect(screen.getByText(data.analyst_paragraph)).toBeInTheDocument();
  expect(screen.getByText(data.confidence_reading)).toBeInTheDocument();
});

test("hides the source breakdown until the toggle is clicked", () => {
  render(<VerdictExplanation data={data} />);
  expect(screen.queryByText("virustotal")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /show source breakdown/i }));
  expect(screen.getByText("virustotal")).toBeInTheDocument();
  expect(screen.getByText("urlscan")).toBeInTheDocument();
});

test("renders nothing when data is null", () => {
  const { container } = render(<VerdictExplanation data={null} />);
  expect(container.firstChild).toBeNull();
});
