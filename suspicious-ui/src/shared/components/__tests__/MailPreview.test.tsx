import { describe, it, expect } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import MailPreview from "@/shared/components/MailPreview";

describe("MailPreview", () => {
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

  it("falls back to 'No preview' inline when the image fails to load", () => {
    render(<MailPreview url="/api/cases/42/mail-preview.png" variant="thumbnail" />);

    const img = screen.getByRole("img");
    fireEvent.error(img);

    expect(screen.getByText(/No preview/i)).toBeInTheDocument();
  });
});
