import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { fireEvent } from "@testing-library/react";
import { AnalyzerEnrichment } from "../AnalyzerEnrichment";

const e = {
  source: "virustotal", malicious_count: 2, total: 70,
  as_owner: "Evil LLC", country: "RU", threat_label: "trojan.emotet",
  vendors: [
    { name: "Kaspersky", category: "malicious", result: "Trojan" },
    { name: "ESET", category: "suspicious", result: "Variant" },
    { name: "Microsoft", category: "undetected", result: null },
  ],
};

describe("AnalyzerEnrichment", () => {
  it("shows the fact grid and the flagged ratio", () => {
    render(<AnalyzerEnrichment enrichment={e} />);
    expect(screen.getByText("Evil LLC")).toBeInTheDocument();
    expect(screen.getByText(/2 \/ 70 security vendors flagged/i)).toBeInTheDocument();
    expect(screen.getByText("trojan.emotet")).toBeInTheDocument();
  });
  it("defaults to flagging vendors only, toggles to all", () => {
    render(<AnalyzerEnrichment enrichment={e} />);
    expect(screen.queryByText("Microsoft")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /show all/i }));
    expect(screen.getByText("Microsoft")).toBeInTheDocument();
  });
});
