/**
 * Tiny "film director" on top of Playwright:
 *  - burned-in subtitles (DOM overlay, so they end up inside the recorded video),
 *  - a visible cursor + click ripple (Playwright videos do not draw the mouse),
 *  - human-paced mouse moves and typing,
 *  - a WebVTT/SRT cue log so the same captions ship as sidecar files.
 */
import type { Locator, Page } from "@playwright/test";

const OVERLAY_INIT = `
(() => {
  const SUB_KEY = "__demo_subtitle";
  const mount = () => {
    if (document.getElementById("__demo_root")) return;
    const root = document.createElement("div");
    root.id = "__demo_root";
    root.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147483647;";
    root.innerHTML = \`
      <style>
        #__demo_sub{position:absolute;left:50%;bottom:26px;transform:translateX(-50%);
          max-width:880px;padding:10px 24px;border-radius:12px;
          background:rgba(12,16,28,.86);color:#fff;text-align:center;
          font:600 22px/1.35 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
          letter-spacing:.1px;box-shadow:0 6px 24px rgba(0,0,0,.35);
          opacity:0;transition:opacity .25s ease;}
        #__demo_sub.on{opacity:1}
        #__demo_cur{position:absolute;left:-40px;top:-40px;width:26px;height:26px;
          transition:transform .12s linear;filter:drop-shadow(0 2px 3px rgba(0,0,0,.45));}
        .__demo_rip{position:absolute;width:14px;height:14px;margin:-7px 0 0 -7px;border-radius:50%;
          border:3px solid #4f6bff;animation:__demo_rip .55s ease-out forwards;}
        @keyframes __demo_rip{to{transform:scale(3.4);opacity:0}}
      </style>
      <div id="__demo_sub"></div>
      <svg id="__demo_cur" viewBox="0 0 24 24"><path d="M3 2l7.5 19 2.7-7.8L21 10.5z"
        fill="#fff" stroke="#111" stroke-width="1.5" stroke-linejoin="round"/></svg>\`;
    document.documentElement.appendChild(root);
    const sub = root.querySelector("#__demo_sub");
    const cur = root.querySelector("#__demo_cur");
    let timer = 0;
    const show = (t, ttl) => {
      clearTimeout(timer);
      if (t) {
        sub.textContent = t; sub.classList.add("on");
        if (ttl) timer = setTimeout(() => { sub.classList.remove("on"); try { sessionStorage.setItem(SUB_KEY, ""); } catch (e) {} }, ttl);
      } else { sub.classList.remove("on"); }
    };
    window.__demoSubtitle = (t, ttl) => { try { sessionStorage.setItem(SUB_KEY, t || ""); } catch (e) {} show(t, ttl); };
    try { const t = sessionStorage.getItem(SUB_KEY); if (t) show(t, 1500); } catch (e) {}
    const place = (x, y) => { cur.style.transform = "translate(" + (x - 3) + "px," + (y - 2) + "px)"; };
    try {
      const p = JSON.parse(sessionStorage.getItem("__demo_pos") || "null");
      if (p) place(p.x, p.y);
    } catch (e) {}
    document.addEventListener("mousemove", (e) => {
      place(e.clientX, e.clientY);
      try { sessionStorage.setItem("__demo_pos", JSON.stringify({ x: e.clientX, y: e.clientY })); } catch (err) {}
    }, true);
    document.addEventListener("mousedown", (e) => {
      const r = document.createElement("div");
      r.className = "__demo_rip";
      r.style.left = e.clientX + "px"; r.style.top = e.clientY + "px";
      root.appendChild(r); setTimeout(() => r.remove(), 600);
    }, true);
  };
  if (document.documentElement) mount();
  else document.addEventListener("DOMContentLoaded", mount);
  new MutationObserver(mount).observe(document, { childList: true });
})();
`;

type Cue = { start: number; end: number; text: string };

export class Director {
  private cues: Cue[] = [];
  private t0 = Date.now();
  private open: { start: number; text: string; ttl: number } | null = null;
  readonly marks: Record<string, number> = {};

  constructor(readonly page: Page) {}

  async prepare() {
    await this.page.addInitScript(OVERLAY_INIT);
    this.t0 = Date.now();
  }

  private now() {
    return (Date.now() - this.t0) / 1000;
  }

  /**
   * Show a caption. It stays up for `holdMs` (default scales with length) plus
   * a short linger, then hides itself. `holdMs = 0` shows it without waiting,
   * so the caption narrates the actions that follow.
   */
  async say(text: string, holdMs?: number, lingerMs = 1200) {
    const dur = holdMs || Math.max(2200, text.length * 48);
    this.closeCue();
    this.open = { start: this.now(), text, ttl: (dur + lingerMs) / 1000 };
    await this.page.evaluate(([t, ttl]) => (window as any).__demoSubtitle?.(t, ttl), [text, dur + lingerMs] as const);
    if (holdMs !== 0) await this.pause(dur);
  }

  /** Remember "now" (seconds into the video) under a name, e.g. the poster frame. */
  mark(name: string) {
    this.marks[name] = this.now();
  }

  async hush() {
    this.closeCue();
    await this.page.evaluate(() => (window as any).__demoSubtitle?.(""));
  }

  private closeCue() {
    if (this.open) {
      this.cues.push({
        start: this.open.start,
        end: Math.min(this.now(), this.open.start + this.open.ttl),
        text: this.open.text,
      });
      this.open = null;
    }
  }

  pause(ms: number) {
    return this.page.waitForTimeout(ms);
  }

  /**
   * Glide the cursor to the centre of an element. Hovering can reflow the page
   * (the slim sidebar expands and shifts its items), so re-measure after the
   * first move and correct if the target moved.
   */
  async glide(target: Locator, steps = 14) {
    await target.scrollIntoViewIfNeeded();
    for (let pass = 0; pass < 3; pass++) {
      const box = await target.boundingBox();
      if (!box) return;
      const x = box.x + box.width / 2;
      const y = box.y + box.height / 2;
      await this.page.mouse.move(x, y, { steps: pass === 0 ? steps : 6 });
      await this.pause(pass === 0 ? 300 : 150);
      const after = await target.boundingBox();
      if (!after || (Math.abs(after.x - box.x) < 2 && Math.abs(after.y - box.y) < 2)) return;
    }
  }

  async click(target: Locator) {
    await this.glide(target);
    await this.page.mouse.down();
    await this.pause(70);
    await this.page.mouse.up();
    await this.pause(350);
  }

  async type(target: Locator, text: string, delay = 55) {
    await this.click(target);
    await this.page.keyboard.type(text, { delay });
    await this.pause(250);
  }

  /** Smooth wheel scroll inside whatever is under the cursor. */
  async scroll(totalPx: number, stepPx = 40) {
    const n = Math.max(1, Math.round(Math.abs(totalPx) / stepPx));
    for (let i = 0; i < n; i++) {
      await this.page.mouse.wheel(0, Math.sign(totalPx) * stepPx);
      await this.pause(28);
    }
    await this.pause(250);
  }

  finish() {
    this.closeCue();
    return this.cues;
  }
}

// ─── Sidecar subtitle files ─────────────────────────────────────────────────

const stamp = (s: number, comma: boolean) => {
  const ms = Math.round(s * 1000);
  const h = String(Math.floor(ms / 3_600_000)).padStart(2, "0");
  const m = String(Math.floor((ms % 3_600_000) / 60_000)).padStart(2, "0");
  const sec = String(Math.floor((ms % 60_000) / 1000)).padStart(2, "0");
  const msr = String(ms % 1000).padStart(3, "0");
  return `${h}:${m}:${sec}${comma ? "," : "."}${msr}`;
};

export function toVtt(cues: Cue[], offset = 0) {
  const body = cues
    .map((c) => `${stamp(c.start + offset, false)} --> ${stamp(c.end + offset, false)}\n${c.text}`)
    .join("\n\n");
  return `WEBVTT\n\n${body}\n`;
}

export function toSrt(cues: Cue[], offset = 0) {
  return (
    cues
      .map((c, i) => `${i + 1}\n${stamp(c.start + offset, true)} --> ${stamp(c.end + offset, true)}\n${c.text}`)
      .join("\n\n") + "\n"
  );
}
