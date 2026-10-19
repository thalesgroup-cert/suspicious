// Feature test and keyboard handling for the 3D map. Plain functions, no three.js: tested without WebGL.

/** What the arrow, +/- and 0 keys drive. The 3D scene implements it; tests use a fake. */
export type MapControlsApi = {
  /** Turn the view: + dTheta moves it round to the right-hand side, + dPhi tips it down (see orbitBy). */
  rotate(dTheta: number, dPhi: number): void;
  /** Multiply the distance to the target (below 1 = closer). */
  zoom(factor: number): void;
  reset(): void;
  clearSelection(): void;
};

export const ROTATE_STEP = Math.PI / 12; // 15 degrees
export const ZOOM_STEP = 1.25;

type KeyEvent = { key: string; ctrlKey?: boolean; metaKey?: boolean; altKey?: boolean; preventDefault(): void };

/** Arrows rotate, +/- zoom, 0 resets, Escape clears the selection. Returns whether the key was taken. Ctrl/Cmd/Alt combinations stay the browser's (page zoom). */
export function handleMapKey(e: KeyEvent, api: MapControlsApi): boolean {
  if (e.ctrlKey || e.metaKey || e.altKey) return false;
  switch (e.key) {
    case "ArrowLeft":
      api.rotate(ROTATE_STEP, 0);
      break;
    case "ArrowRight":
      api.rotate(-ROTATE_STEP, 0);
      break;
    case "ArrowUp":
      api.rotate(0, ROTATE_STEP);
      break;
    case "ArrowDown":
      api.rotate(0, -ROTATE_STEP);
      break;
    case "+":
    case "=":
      api.zoom(1 / ZOOM_STEP);
      break;
    case "-":
    case "_":
      api.zoom(ZOOM_STEP);
      break;
    case "0":
      api.reset();
      break;
    case "Escape":
      api.clearSelection();
      break;
    default:
      return false;
  }
  e.preventDefault();
  return true;
}

let webgl: boolean | undefined;

/**
 * Whether this browser can make a WebGL 2 context, which is what three.js (r163 and later) draws with: a browser that only has
 * WebGL 1 gets the 2D map, not a 3D one that fails to start. Asked once; the test context is given straight back.
 */
export function detectWebGL(): boolean {
  if (webgl !== undefined) return webgl;
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl2");
    webgl = !!gl;
    // Browsers allow about 16 live contexts: do not spend one on a question.
    gl?.getExtension("WEBGL_lose_context")?.loseContext();
  } catch {
    webgl = false;
  }
  return webgl;
}

/** For tests: forget the answer. */
export function resetWebGLDetection() {
  webgl = undefined;
}
