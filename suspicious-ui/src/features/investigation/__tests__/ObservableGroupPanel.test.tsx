import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ObservableGroupPanel } from "../ObservableGroupPanel";

const group = {
  observables: [{
    value: "8.8.8.8", type: "ip",
    verdict: { band: "Safe", confidence: 90, rationale: ["GTI (authoritative) reports clean."] },
    sources: [
      {
        name: "GTI", tier: 1, verdict: "clean", confidence: 95, evidence: "0 detections", failed: false, report: {},
        enrichment: { source: "virustotal", as_owner: "Google LLC", vendors: [] },
      },
      { name: "AbuseIPDB", tier: 3, verdict: "suspicious", confidence: 30, evidence: "conf 12%", failed: false, report: {} },
    ],
  }],
};

describe("ObservableGroupPanel", () => {
  it("shows the trusted-source ratio and per-observable verdict", () => {
    render(<ObservableGroupPanel group={group} />);
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText(/1 \/ 2/)).toBeInTheDocument(); // 1 of 2 sources flagged
    expect(screen.getByText("Safe")).toBeInTheDocument();
  });

  it("renders VT enrichment for a source that carries it", () => {
    render(<ObservableGroupPanel group={group} />);
    // MUI Accordion keeps collapsed content mounted, so no clicks needed.
    expect(screen.getByText("Google LLC")).toBeInTheDocument();
  });
});
