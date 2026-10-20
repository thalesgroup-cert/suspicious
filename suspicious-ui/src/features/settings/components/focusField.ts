/** Scrolls to the input of a config key and focuses it. Smooth scrolling only when the user has not asked for less motion. */
export function focusField(key: string) {
  const el = document.querySelector<HTMLElement>(`[data-field="${CSS.escape(key)}"]`);
  if (!el) return;
  const reduce = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.scrollIntoView({ block: "center", behavior: reduce ? "auto" : "smooth" });
  el.focus({ preventScroll: true });
}
