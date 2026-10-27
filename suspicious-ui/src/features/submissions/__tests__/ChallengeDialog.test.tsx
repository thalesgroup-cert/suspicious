import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ChallengeDialog, MIN_CHALLENGE_REASON } from "@/features/submissions/components/ChallengeDialog";

function setup(props: Partial<React.ComponentProps<typeof ChallengeDialog>> = {}) {
  const onClose = vi.fn();
  const onSubmit = vi.fn();
  render(<ChallengeDialog caseId={42} onClose={onClose} onSubmit={onSubmit} pending={false} error={false} {...props} />);
  return { onClose, onSubmit, user: userEvent.setup() };
}

const submit = () => screen.getByRole("button", { name: /^(confirm|sending…)$/i });
const reasonBox = () => screen.getByLabelText(/why is the verdict wrong/i);

describe("ChallengeDialog", () => {
  it("renders nothing without a case", () => {
    render(<ChallengeDialog caseId={null} onClose={vi.fn()} onSubmit={vi.fn()} pending={false} error={false} />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("names the case it is about", () => {
    setup();
    expect(screen.getByRole("dialog", { name: /challenge/i })).toBeInTheDocument();
    expect(screen.getByText(/#42/)).toBeInTheDocument();
  });

  it("keeps Confirm off until a verdict is picked and the reason is long enough", async () => {
    const { user } = setup();
    expect(submit()).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Dangerous" }));
    expect(submit()).toBeDisabled();

    await user.type(reasonBox(), "x".repeat(MIN_CHALLENGE_REASON - 1));
    expect(submit()).toBeDisabled();

    await user.type(reasonBox(), "x");
    expect(submit()).toBeEnabled();
  });

  it("does not count surrounding spaces towards the reason", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: "Safe" }));
    await user.type(reasonBox(), "   short   ");
    expect(submit()).toBeDisabled();
  });

  it("submits the case, the verdict and the trimmed reason", async () => {
    const { user, onSubmit } = setup();
    await user.click(screen.getByRole("button", { name: "Dangerous" }));
    await user.type(reasonBox(), "  it is a real phish  ");
    await user.click(submit());
    expect(onSubmit).toHaveBeenCalledWith({ id: 42, proposed_result: "Dangerous", reason: "it is a real phish" });
  });

  it("is disabled while the request is in flight", async () => {
    const { user } = setup({ pending: true });
    await user.click(screen.getByRole("button", { name: "Safe" }));
    await user.type(reasonBox(), "a perfectly good reason");
    expect(submit()).toBeDisabled();
  });

  it("shows the failure message", () => {
    setup({ error: true });
    expect(screen.getByRole("alert")).toHaveTextContent(/failed to challenge/i);
  });

  it("Cancel closes it", async () => {
    const { user, onClose, onSubmit } = setup();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("starts empty for the next case after being closed", async () => {
    const user = userEvent.setup();
    const props = { onClose: vi.fn(), onSubmit: vi.fn(), pending: false, error: false };
    const { rerender } = render(<ChallengeDialog caseId={42} {...props} />);
    await user.click(screen.getByRole("button", { name: "Safe" }));
    await user.type(reasonBox(), "first reason entered");

    rerender(<ChallengeDialog caseId={null} {...props} />);
    rerender(<ChallengeDialog caseId={43} {...props} />);

    expect(reasonBox()).toHaveValue("");
    expect(screen.getByRole("button", { name: "Safe" })).toHaveAttribute("aria-pressed", "false");
    expect(submit()).toBeDisabled();
  });
});
