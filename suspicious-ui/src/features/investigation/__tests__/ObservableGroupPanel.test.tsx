import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ObservableGroupPanel } from "../ObservableGroupPanel";
import { parseObservableGroup } from "../observableGroup";

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

  it("survives one source's enrichment having a type-invalid field", () => {
    // `asn` must be a number per enrichmentSchema — a string here used to fail
    // the whole observableGroupSchema parse and blank the panel. `.catch(undefined)`
    // drops just the bad enrichment; the rest of the payload still parses.
    const raw = {
      observables: [{
        value: "8.8.8.8", type: "ip",
        verdict: { band: "Safe", confidence: 90, rationale: ["clean"] },
        sources: [
          {
            name: "GTI", tier: 1, verdict: "clean", confidence: 95, evidence: "0 detections",
            failed: false, report: {},
            enrichment: { source: "virustotal", asn: "AS15169", vendors: [] },
          },
          { name: "AbuseIPDB", tier: 3, verdict: "suspicious", confidence: 30, evidence: "conf 12%", failed: false, report: {} },
        ],
      }],
    };
    const parsed = parseObservableGroup(raw);
    expect(parsed).toBeDefined();
    render(<ObservableGroupPanel group={parsed!} />);
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("AbuseIPDB")).toBeInTheDocument();
  });

  it("shows extraction provenance on a derived observable", () => {
    const groupWithDerived = {
      observables: [
        {
          value: "https://tinyurl.com/x", type: "url",
          verdict: { band: "Dangerous", confidence: 80, rationale: [] },
          sources: [],
          derived_from: null,
          escalation_note: "Escalated to Dangerous: UnshortenLink_1_2 extracted https://evil.example/login → Dangerous.",
        },
        {
          value: "https://evil.example/login", type: "url",
          verdict: { band: "Dangerous", confidence: 90, rationale: [] },
          sources: [],
          derived_from: { value: "https://tinyurl.com/x", via_analyzer: "UnshortenLink_1_2" },
          escalation_note: "",
        },
      ],
    };
    render(<ObservableGroupPanel group={groupWithDerived} />);
    expect(screen.getByText(/extracted from/i)).toBeInTheDocument();
    expect(screen.getByText(/Escalated to Dangerous/)).toBeInTheDocument();
  });
});
