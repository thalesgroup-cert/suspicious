import { render, screen } from "@testing-library/react";
import { test, expect } from "vitest";
import { ThreatBadge } from "../ThreatBadge";
import { AnalysisHealthBanner } from "../AnalysisHealthBanner";
import { SourceTable } from "../SourceTable";
import type { AnalysisHealth } from "../api";

const health = (over: Partial<AnalysisHealth> = {}): AnalysisHealth => ({
  total: 11, failed: 0, pending: 0, failures: [], ...over,
});

test("threat badge shows the label", () => {
  render(<ThreatBadge value={{ label: "trojan.emotet", category: "trojan", source: "virustotal" }} />);
  expect(screen.getByText("trojan.emotet")).toBeInTheDocument();
});

test("threat badge renders nothing without a classification", () => {
  const { container } = render(<ThreatBadge value={null} />);
  expect(container).toBeEmptyDOMElement();
});

test("health banner is hidden when nothing failed or is pending", () => {
  const { container } = render(<AnalysisHealthBanner health={health()} />);
  expect(container).toBeEmptyDOMElement();
});

test("health banner names the failed analyzers and the effect on confidence", () => {
  render(
    <AnalysisHealthBanner
      health={health({
        failed: 2,
        failures: [
          { analyzer: "Shodan", target: "1.2.3.4", status: "Failure" },
          { analyzer: "Urlscan", target: "http://x.test", status: "Failure" },
        ],
      })}
    />,
  );
  expect(screen.getByText(/2 of 11 analyzers failed/i)).toBeInTheDocument();
  expect(screen.getByText(/Shodan/)).toBeInTheDocument();
  expect(screen.getByText(/Urlscan/)).toBeInTheDocument();
  expect(screen.getByText(/lower confidence/i)).toBeInTheDocument();
});

test("health banner mentions analyzers still running", () => {
  render(<AnalysisHealthBanner health={health({ pending: 3 })} />);
  expect(screen.getByText(/3 analyzers still running/i)).toBeInTheDocument();
});

test("health banner uses singular wording for one analyzer", () => {
  render(
    <AnalysisHealthBanner
      health={health({ total: 5, failed: 1, failures: [{ analyzer: "Shodan", target: "1.2.3.4", status: "Failure" }] })}
    />,
  );
  expect(screen.getByText(/1 of 5 analyzers failed/i)).toBeInTheDocument();
});

test("source table flags a failed source", () => {
  render(
    <SourceTable
      sources={[
        { name: "GTI", tier: 1, verdict: "no-data", confidence: null, evidence: "", failed: true, report: {} },
        { name: "AbuseIPDB", tier: 3, verdict: "clean", confidence: 30, evidence: "ok", failed: false, report: {} },
      ] as never}
    />,
  );
  expect(screen.getAllByText("failed")).toHaveLength(1);
});
