import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import MailPreview from "@/shared/components/MailPreview";

describe("MailPreview", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders nothing for thumbnail when url is missing", () => {
    const { container } = render(<MailPreview url={null} variant="thumbnail" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the 'No preview' block in full mode when url is missing", () => {
    render(<MailPreview url={null} variant="full" />);
    expect(
      screen.getByText(/No email preview available for this case/i)
    ).toBeInTheDocument();
  });

  it("renders an <img> with the given url and alt text", () => {
    render(
      <MailPreview
        url="/api/cases/42/mail-preview.png"
        variant="full"
        alt="case-42-preview"
      />
    );
    const img = screen.getByRole("img", { name: "case-42-preview" }) as HTMLImageElement;
    expect(img).toBeInTheDocument();
    expect(img.src).toContain("/api/cases/42/mail-preview.png");
  });

  it("falls back to 'No preview' immediately on error when retries are disabled", () => {
    render(
      <MailPreview url="/api/cases/42/mail-preview.png" variant="thumbnail" maxRetries={0} />
    );

    fireEvent.error(screen.getByRole("img"));

    expect(screen.getByText(/^No preview$/i)).toBeInTheDocument();
  });

  it("retries with a cache-busting param before giving up", () => {
    vi.useFakeTimers();
    render(
      <MailPreview
        url="/api/cases/42/mail-preview.png"
        variant="full"
        maxRetries={1}
        retryDelayMs={1000}
      />
    );

    // First failure schedules a retry — not "No preview" yet.
    fireEvent.error(screen.getByRole("img"));
    expect(screen.queryByText(/^No preview$/i)).toBeNull();

    // After the delay the <img> remounts with a cache-busting query param.
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    const retried = screen.getByRole("img") as HTMLImageElement;
    expect(retried.src).toContain("r=1");

    // The retry also fails — retries exhausted, fall back to "No preview".
    fireEvent.error(retried);
    expect(screen.getByText(/^No preview$/i)).toBeInTheDocument();
  });
});
