import * as React from "react";
import { Box, Button, Stack, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery } from "@mui/material";
import { alpha, useTheme, type Theme } from "@mui/material/styles";
import { RestartAltOutlined } from "@mui/icons-material";
import { Canvas } from "@react-three/fiber";

import { plural } from "@/features/dashboard/format";
import type { CampaignRow, PcaPoint } from "@/features/campaigns/api";
import {
  INITIAL_POSITION,
  MIN_CLOUD_POINTS,
  NEAREST,
  axisSegments,
  bounds,
  caseIdToCampaign,
  categoryEllipsoid,
  nearest,
  normalise,
  toScene,
  topCampaigns,
  type Vec3,
} from "@/features/campaigns/geometry";
import {
  ageEnds,
  campaignPalette,
  mapDescription,
  pointColours,
  uniqueDates,
  visibleMask,
  type ColourMode,
} from "@/features/campaigns/mapModel";
import { handleMapKey, type MapControlsApi } from "@/features/campaigns/mapSupport";
import { MAP_HEIGHT, SERIES, classKey, formatFullDay, useClassColors, type SeriesKey } from "@/features/campaigns/utils";
import { ensureContrast, flatten } from "@/shared/lib/contrast";
import ClassChip from "./ClassChip";
import { AgeLegend, CampaignLegend } from "./MapLegend";
import MapScene, { type SceneApi } from "./MapScene";
import MapTooltip from "./MapTooltip";

export type EmbeddingMap3DProps = {
  points: PcaPoint[];
  explainedVariance: number[];
  campaigns: CampaignRow[];
  /** How many case ids the summary lists per campaign, for the legend's wording (0 when unknown). */
  maxCaseIds?: number;
  selectedCaseIds: string[];
  onSelectCases: (caseIds: string[]) => void;
};

// Reddish purple from the same colour-blind-safe set as the campaign colours: unlike the age ramp's blue-greys it cannot be mistaken for "oldest".
const NO_DATE_COLOUR = "#CC79A7";

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** One end of the date range: label, slider over the days present, and the chosen day in text. Three cells of the parent's grid. */
function RangeRow({ id, label, max, value, day, onChange }: { id: string; label: string; max: number; value: number; day: string; onChange: (position: number) => void }) {
  const accent = useTheme().palette.primary.main;
  return (
    <>
      <Typography component="label" htmlFor={id} variant="caption" color="text.secondary">
        {label}
      </Typography>
      <Box
        component="input"
        id={id}
        type="range"
        min={0}
        max={max}
        step={1}
        value={value}
        aria-valuetext={day}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(Number(e.target.value))}
        sx={{ accentColor: accent, flex: 1, minWidth: 0, m: 0 }}
      />
      <Typography variant="caption">{day}</Typography>
    </>
  );
}

/**
 * The 3D map: an R3F canvas plus every control and piece of text that must exist outside it, because a canvas
 * is invisible to assistive technology (WCAG 1.1.1, 2.1.1): a named and described group, key controls, chips, the date range and the legends.
 */
export default function EmbeddingMap3D({ points, explainedVariance, campaigns, maxCaseIds = 0, selectedCaseIds, onSelectCases }: EmbeddingMap3DProps) {
  const theme = useTheme();
  const classColors = useClassColors();
  const reducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)", { noSsr: true });
  const ids = { description: React.useId(), key: React.useId(), from: React.useId(), to: React.useId() };

  const [mode, setMode] = React.useState<ColourMode>("category");
  const [hidden, setHidden] = React.useState<SeriesKey[]>([]);
  const [span, setSpan] = React.useState<[number, number] | null>(null);
  const [hover, setHover] = React.useState<{ index: number; x: number; y: number; width: number } | null>(null);
  const [lost, setLost] = React.useState(false);
  if (lost) throw new Error("The WebGL context was lost");

  const box = React.useRef<HTMLDivElement>(null);
  const keyRegion = React.useRef<HTMLDivElement>(null);
  const sceneApi = React.useRef<SceneApi | null>(null);
  const labels = React.useRef<(HTMLElement | null)[]>([]);
  const pickedKey = React.useRef<string | null>(null);

  // ---- theme colours for the canvas (it cannot read CSS variables)
  const bg = theme.palette.background.paper;
  const paint = React.useMemo(
    () => ({
      background: bg,
      axis: flatten(theme.palette.text.secondary, bg, 0.6),
      outline: flatten(theme.palette.text.primary, bg),
      neighbourOutline: flatten(theme.palette.text.secondary, bg),
      label: ensureContrast(flatten(theme.palette.text.secondary, bg), bg, 4.5),
    }),
    [bg, theme.palette.text.primary, theme.palette.text.secondary]
  );

  // ---- what is in the sample
  const norm = React.useMemo(() => normalise(points), [points]);
  const box3 = React.useMemo(() => bounds(points), [points]);
  const positions = React.useMemo(() => points.map((p) => toScene([p.x, p.y, p.z], norm)), [points, norm]);
  const classes = React.useMemo(() => points.map((p) => classKey(p.label)), [points]);
  const counts = React.useMemo(() => {
    const m = new Map<SeriesKey, number>();
    for (const k of classes) m.set(k, (m.get(k) ?? 0) + 1);
    return m;
  }, [classes]);
  const series = SERIES.filter(([k]) => counts.has(k));
  const dates = React.useMemo(() => uniqueDates(points), [points]);
  const undated = points.filter((p) => !p.date).length;

  // ---- filters
  const last = Math.max(0, dates.length - 1);
  const lo = clamp(span?.[0] ?? 0, 0, last);
  const hi = clamp(span?.[1] ?? last, lo, last);
  const narrowed = dates.length > 1 && (lo > 0 || hi < last);
  const hiddenSet = React.useMemo(() => new Set(hidden), [hidden]);
  const mask = React.useMemo(
    () => visibleMask(points, hiddenSet, narrowed ? { from: dates[lo], to: dates[hi] } : null),
    [points, hiddenSet, narrowed, dates, lo, hi]
  );
  const shown = mask.filter(Boolean).length;

  // ---- colours
  const ranked = React.useMemo(() => topCampaigns(campaigns, 6), [campaigns]);
  const campaignOf = React.useMemo(() => caseIdToCampaign(ranked), [ranked]);
  const campaignColours = React.useMemo(() => campaignPalette(bg), [bg]);
  const neutral = React.useMemo(() => ensureContrast(flatten(theme.palette.text.secondary, bg), bg, 3), [bg, theme.palette.text.secondary]);
  const ends = React.useMemo(
    () => ageEnds(bg, flatten(theme.palette.text.secondary, bg), theme.palette.primary.main),
    [bg, theme.palette.text.secondary, theme.palette.primary.main]
  );
  const noDate = React.useMemo(() => ensureContrast(NO_DATE_COLOUR, bg, 3), [bg]);
  const colours = React.useMemo(
    () =>
      pointColours(points, mode, {
        classColors,
        campaignOf,
        campaignColours,
        neutral,
        age: { min: dates[0] ?? "", max: dates[last] ?? "", old: ends.old, newest: ends.newest, none: noDate },
      }),
    [points, mode, classColors, campaignOf, campaignColours, neutral, dates, last, ends, noDate]
  );
  const inMap = React.useMemo(() => {
    const n = ranked.map(() => 0);
    for (const p of points) {
      const i = p.suspicious_case_id ? campaignOf.get(p.suspicious_case_id) : undefined;
      if (i !== undefined) n[i]++;
    }
    return n;
  }, [points, ranked, campaignOf]);

  // ---- clouds: one per category with enough points shown
  const clouds = React.useMemo(() => {
    const byClass = new Map<SeriesKey, PcaPoint[]>();
    points.forEach((p, i) => {
      if (!mask[i]) return;
      const list = byClass.get(classes[i]);
      if (list) list.push(p);
      else byClass.set(classes[i], [p]);
    });
    return [...byClass].flatMap(([k, list]) => {
      const e = categoryEllipsoid(list);
      return e ? [{ key: k, colour: classColors[k], centre: toScene(e.center, norm), axes: e.axes, radii: e.radii.map((r) => r * norm.scale) as Vec3 }] : [];
    });
  }, [points, mask, classes, classColors, norm]);

  // ---- selection: the cases chosen on the page, and the closest points to a single one
  const byCase = React.useMemo(() => {
    const m = new Map<string, number[]>();
    points.forEach((p, i) => {
      if (!p.suspicious_case_id) return;
      const list = m.get(p.suspicious_case_id);
      if (list) list.push(i);
      else m.set(p.suspicious_case_id, [i]);
    });
    return m;
  }, [points]);
  const selected = React.useMemo(() => selectedCaseIds.flatMap((id) => byCase.get(id) ?? []).filter((i) => mask[i]), [selectedCaseIds, byCase, mask]);
  const neighbours = React.useMemo(
    () => (selectedCaseIds.length === 1 && selected.length ? nearest(points, selected[0], NEAREST).map((n) => n.index).filter((i) => mask[i]) : []),
    [selectedCaseIds.length, selected, points, mask]
  );
  const selectedKey = selectedCaseIds.join("\n");
  const focus = React.useMemo(() => {
    if (!selected.length) return null;
    const target = [0, 1, 2].map((a) => selected.reduce((s, i) => s + positions[i][a], 0) / selected.length) as Vec3;
    return { key: selectedKey, target };
  }, [selected, selectedKey, positions]);

  const axes = React.useMemo(() => (box3 ? axisSegments(box3).map((s) => ({ from: toScene(s.from, norm), to: toScene(s.to, norm) })) : []), [box3, norm]);
  const axisLabels = [0, 1, 2].map((i) => `PC${i + 1}${explainedVariance[i] === undefined ? "" : ` ${Math.round(explainedVariance[i] * 100)}%`}`);
  // The real values behind the normalised box, as text: on the canvas they would crowd the labels.
  const ranges = box3 ? `Axis ranges: ${[0, 1, 2].map((i) => `PC${i + 1} ${box3.min[i].toFixed(2)} to ${box3.max[i].toFixed(2)}`).join(", ")}.` : null;

  // ---- events
  const onHover = React.useCallback((index: number | null, clientX = 0, clientY = 0) => {
    const rect = box.current?.getBoundingClientRect();
    setHover(index === null || !rect ? null : { index, x: clientX - rect.left, y: clientY - rect.top, width: rect.width });
  }, []);
  const onPick = React.useCallback(
    (index: number) => {
      const id = points[index]?.suspicious_case_id;
      if (!id) return;
      // The camera follows selections made elsewhere on the page, not clicks in the map itself.
      pickedKey.current = id;
      onSelectCases([id]);
    },
    [points, onSelectCases]
  );

  // True while the selection is the one the user just clicked; the first different selection forgets it.
  const consumeSkip = React.useCallback((key: string) => {
    if (pickedKey.current === key) return true;
    pickedKey.current = null;
    return false;
  }, []);

  const controls: MapControlsApi = {
    rotate: (dTheta, dPhi) => sceneApi.current?.rotate(dTheta, dPhi),
    zoom: (f) => sceneApi.current?.zoom(f),
    reset: () => sceneApi.current?.reset(),
    clearSelection: () => onSelectCases([]),
  };
  const toggle = (k: SeriesKey) => setHidden((h) => (h.includes(k) ? h.filter((x) => x !== k) : [...h, k]));
  const setFrom = (v: number) => setSpan([Math.min(v, hi), hi]);
  const setTo = (v: number) => setSpan([lo, Math.max(v, lo)]);

  const hovered = hover ? points[hover.index] : undefined;

  return (
    <Box>
      <Stack direction="row" useFlexGap spacing={1} sx={{ mb: 1, alignItems: "center", flexWrap: "wrap" }}>
        <Typography variant="caption" color="text.secondary" aria-hidden>
          Colour by
        </Typography>
        <ToggleButtonGroup size="small" exclusive aria-label="Colour by" value={mode} onChange={(_, v: ColourMode | null) => v && setMode(v)}>
          <ToggleButton value="category">Category</ToggleButton>
          <ToggleButton value="campaign">Campaign</ToggleButton>
          <ToggleButton value="age">Age</ToggleButton>
        </ToggleButtonGroup>
        <Button size="small" startIcon={<RestartAltOutlined />} onClick={controls.reset} sx={{ ml: "auto" }}>
          Reset view
        </Button>
      </Stack>

      <Stack direction="row" useFlexGap spacing={0.75} sx={{ flexWrap: "wrap", mb: 1 }}>
        {series.map(([k, label]) => (
          <ClassChip key={k} k={k} label={`${label} ${counts.get(k)}`} on={!hiddenSet.has(k)} clickable aria-pressed={!hiddenSet.has(k)} onClick={() => toggle(k)} />
        ))}
      </Stack>

      <Box sx={{ mb: 1 }}>
        {dates.length > 1 ? (
          <Box sx={{ display: "grid", gridTemplateColumns: "auto minmax(80px, 1fr) 7.5em", columnGap: 1, rowGap: 0.25, alignItems: "center" }}>
            <RangeRow id={ids.from} label="From" max={last} value={lo} day={formatFullDay(dates[lo])} onChange={setFrom} />
            <RangeRow id={ids.to} label="To" max={last} value={hi} day={formatFullDay(dates[hi])} onChange={setTo} />
          </Box>
        ) : points.length ? (
          <Typography variant="caption" color="text.secondary" component="p">
            {dates.length === 1 ? `Every dated message is from ${formatFullDay(dates[0])}.` : "No message in this sample has a date."}
          </Typography>
        ) : null}
        {/* Polite: a screen reader hears the new count after each change, not each step of a drag. */}
        <Typography role="status" aria-live="polite" variant="caption" component="p" sx={{ mt: 0.5 }}>
          {`${shown} of ${points.length} messages shown`}
        </Typography>
        {narrowed && undated ? (
          <Typography variant="caption" color="text.secondary" component="p">
            {`${plural(undated, "message")} without a date ${undated === 1 ? "is" : "are"} hidden while the range is narrowed.`}
          </Typography>
        ) : null}
      </Box>

      <Typography id={ids.description} variant="caption" color="text.secondary" component="p" sx={{ mb: 0.5 }}>
        {mapDescription(points)}
      </Typography>
      <Box
        component="a"
        href={`#${ids.key}`}
        onClick={(e: React.MouseEvent) => {
          e.preventDefault();
          keyRegion.current?.focus();
        }}
        // Visually hidden until it has focus. (In sx a bare 1 is 100%, not 1px: that once made the page scroll sideways on a phone.)
        sx={{
          position: "absolute",
          width: "1px",
          height: "1px",
          m: "-1px",
          p: 0,
          overflow: "hidden",
          clip: "rect(0 0 0 0)",
          whiteSpace: "nowrap",
          color: (t: Theme) => `var(--campaigns-link, ${t.palette.primary.main})`,
          "&:focus": { position: "static", width: "auto", height: "auto", m: 0, clip: "auto", overflow: "visible", display: "inline-block", mb: 0.5 },
        }}
      >
        Skip map
      </Box>

      <Box
        role="group"
        aria-label="3D embedding map"
        aria-describedby={ids.description}
        tabIndex={0}
        onKeyDown={(e: React.KeyboardEvent) => {
          handleMapKey(e, controls);
        }}
        // 24px each side that is not the canvas: on a phone, a finger there scrolls the page.
        sx={{ px: 3, borderRadius: 2, "&:focus-visible": { outline: `2px solid ${theme.palette.primary.main}`, outlineOffset: 2 } }}
      >
        <Box
          ref={box}
          onPointerLeave={() => setHover(null)}
          sx={{ position: "relative", height: MAP_HEIGHT, border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden", touchAction: "none", bgcolor: "background.paper" }}
        >
          <Canvas
            frameloop="demand"
            flat
            dpr={[1, 2]}
            camera={{ fov: 45, near: 0.05, far: 80, position: INITIAL_POSITION }}
            gl={{ antialias: true, powerPreference: "high-performance" }}
            aria-hidden
            onCreated={({ gl }) => {
              gl.domElement.addEventListener("webglcontextlost", (e) => {
                e.preventDefault();
                setLost(true);
              });
            }}
          >
            <MapScene
              positions={positions}
              colours={colours}
              visible={mask}
              selected={selected}
              neighbours={neighbours}
              hovered={hover?.index ?? null}
              clouds={clouds}
              axes={axes}
              paint={paint}
              reducedMotion={reducedMotion}
              focus={focus}
              consumeSkip={consumeSkip}
              apiRef={sceneApi}
              labelRefs={labels}
              onHover={onHover}
              onPick={onPick}
              fitKey={points}
            />
          </Canvas>
          {axisLabels.map((text, i) => (
            <Typography
              key={i}
              ref={(el: HTMLElement | null) => {
                labels.current[i] = el;
              }}
              aria-hidden
              variant="caption"
              sx={{ position: "absolute", left: 0, top: 0, visibility: "hidden", whiteSpace: "nowrap", pointerEvents: "none", color: paint.label, bgcolor: alpha(bg, 0.7), px: 0.5, borderRadius: 0.5 }}
            >
              {text}
            </Typography>
          ))}
          {hover && hovered ? (
            <Box aria-hidden sx={{ position: "absolute", left: Math.max(4, Math.min(hover.x + 14, hover.width - 290)), top: hover.y + 14, pointerEvents: "none", zIndex: 1 }}>
              <MapTooltip point={hovered} />
            </Box>
          ) : null}
        </Box>
      </Box>

      <Box ref={keyRegion} id={ids.key} role="group" aria-label="Map key" tabIndex={-1} sx={{ mt: 1 }}>
        {mode === "campaign" ? <CampaignLegend campaigns={ranked} colours={campaignColours} neutral={neutral} inMap={inMap} maxCaseIds={maxCaseIds} /> : null}
        {mode === "age" ? <AgeLegend oldest={dates[0] ?? null} newest={dates[last] ?? null} from={ends.old} to={ends.newest} none={noDate} hasUndated={undated > 0} /> : null}
        {clouds.length ? (
          <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>
            Shaded clouds: 2 standard deviations around each category&apos;s average position, computed from the points shown.
          </Typography>
        ) : null}
        {ranges ? (
          <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>
            {ranges}
          </Typography>
        ) : null}
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5 }}>
          Drag to rotate, scroll to zoom, right-drag to pan, click a point to select it. Clouds need at least {MIN_CLOUD_POINTS} points.
        </Typography>
        <Typography variant="caption" color="text.secondary" component="p" sx={{ display: "none", "@media (pointer: coarse)": { display: "block" } }}>
          Touch: one finger rotates, two fingers zoom. Scroll the page from the margins either side of the map.
        </Typography>
      </Box>
    </Box>
  );
}
