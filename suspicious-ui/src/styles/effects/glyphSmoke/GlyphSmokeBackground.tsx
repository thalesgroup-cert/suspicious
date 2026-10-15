import * as React from "react";
import { createGlyphSmoke, type GlyphSmoke, type GlyphSmokePalette } from "./engine";

const LOGO_URL = "/icons/suspicious-logo.png";

type Props = {
  palette?: Partial<GlyphSmokePalette>;
};

/**
 * Full-viewport canvas behind the app: drifting glyph smoke, glyphs that light up under the pointer,
 * and a click that sends the Suspicious logo rippling out as blue light.
 * It sits at z-index -1 and ignores the pointer; listeners are on `window`, so the UI above stays clickable.
 */
export function GlyphSmokeBackground({ palette }: Props) {
  const ref = React.useRef<HTMLCanvasElement>(null);

  React.useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const reduced = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const smoke: GlyphSmoke | null = createGlyphSmoke(canvas, { logoUrl: LOGO_URL, palette, reducedMotion: reduced });
    if (!smoke) return; // no 2D context: leave the plain theme background

    if (import.meta.env.MODE !== "production") (canvas as HTMLCanvasElement & { __glyphSmoke?: GlyphSmoke }).__glyphSmoke = smoke;

    const onMove = (e: PointerEvent) => smoke.pointer(e.clientX, e.clientY);
    const onLeave = () => smoke.pointer(null);
    const onDown = (e: PointerEvent) => smoke.ripple(e.clientX, e.clientY);
    const onResize = () => smoke.resize();
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerdown", onDown, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    window.addEventListener("resize", onResize);
    smoke.start();

    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onDown);
      document.documentElement.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("resize", onResize);
      smoke.destroy();
    };
  }, [palette]);

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      data-testid="glyph-smoke"
      style={{ position: "fixed", inset: 0, width: "100%", height: "100%", zIndex: -1, pointerEvents: "none", display: "block" }}
    />
  );
}
