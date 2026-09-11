import { test, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ScreenshotPanel } from "../ScreenshotPanel";

test("renders an img with the given src", () => {
  render(<ScreenshotPanel src="/api/cases/1/screenshot.png" label="Page screenshot" />);
  expect(screen.getByRole("img", { name: /page screenshot/i })).toHaveAttribute(
    "src", "/api/cases/1/screenshot.png");
});

test("shows fallback when src is null", () => {
  render(<ScreenshotPanel src={null} label="Page screenshot" />);
  expect(screen.getByText(/no screenshot available/i)).toBeInTheDocument();
});

test("shows fallback after the image errors", () => {
  render(<ScreenshotPanel src="/bad.png" label="Page screenshot" />);
  fireEvent.error(screen.getByRole("img"));
  expect(screen.getByText(/no screenshot available/i)).toBeInTheDocument();
});
