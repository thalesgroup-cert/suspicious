# mail_service/email_theme.py
"""
Maps a UserProfile's theme + semantic_colors to a flat dict of
email-safe inline CSS values.

All colors are sourced directly from src/styles/themes.ts to ensure
the email palette exactly matches what the user sees in the web UI.

Every palette key is intentionally a plain hex string — no alpha(),
no CSS variables — so they can be dropped straight into style=""
attributes. Email clients strip <style> blocks and don't support
CSS custom properties.

Usage:
    from .email_theme import resolve_email_theme
    from profiles.models import UserProfile

    profile = UserProfile.objects.filter(user=case.reporter).first()
    ctx = resolve_email_theme(profile)
    template.render(**ctx, ...)
"""

from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# Palette definitions — sourced 1-to-1 from themes.ts
#
# Key mapping
#   bg          palette.background.default
#   surface     palette.background.paper
#   header_bg   darkest tone (paper for dark themes; near-black for light)
#   header_text palette.text.primary  (contrast on header_bg)
#   accent      palette.primary.main
#   accent_text legible colour on top of accent
#   body_text   palette.text.primary
#   muted       palette.text.secondary (~70 % opacity of text.primary)
#   border      MuiCard/MuiPaper border colour (composited to opaque hex)
#   link        primary or secondary used for inline links
#   cta_bg      palette.primary.main
#   cta_text    legible on cta_bg
# ---------------------------------------------------------------------------

THEME_PALETTES: dict[str, dict[str, str]] = {

    # ── 1. MIDNIGHT ───────────────────────────────────────────────────────
    # bg:#03050D  paper:#080D1A  primary:#4D8FFF  text:#E6ECF8
    # MuiPaper border: alpha(#4D8FFF, 0.12) composited on #03050D → #0D1E3A
    "midnight": {
        "bg":          "#03050D",
        "surface":     "#080D1A",
        "header_bg":   "#03050D",
        "header_text": "#E6ECF8",
        "accent":      "#4D8FFF",
        "accent_text": "#03050D",
        "body_text":   "#E6ECF8",
        "muted":       "#7A91B8",
        "border":      "#0D1E3A",
        "link":        "#03050D",
        "cta_bg":      "#4D8FFF",
        "cta_text":    "#03050D",
    },

    # ── 2. GRAPHITE ───────────────────────────────────────────────────────
    # bg:#0A0C10  paper:#10141C  primary:#4FB3FF  text:#E8EDF4
    # MuiPaper border: rgba(229,231,235,.10) on #0A0C10 → #1C2028
    "graphite": {
        "bg":          "#0A0C10",
        "surface":     "#10141C",
        "header_bg":   "#0A0C10",
        "header_text": "#E8EDF4",
        "accent":      "#4FB3FF",
        "accent_text": "#0A0C10",
        "body_text":   "#E8EDF4",
        "muted":       "#7A8A9C",
        "border":      "#1C2028",
        "link":        "#0A0C10",
        "cta_bg":      "#4FB3FF",
        "cta_text":    "#0A0C10",
    },

    # ── 3. SLATE ──────────────────────────────────────────────────────────
    # bg:#08101E  paper:#0E1830  primary:#5D9EFF  text:#DDE8F8
    # No explicit paper border override; using alpha(#5D9EFF,0.12) → #142040
    "slate": {
        "bg":          "#08101E",
        "surface":     "#0E1830",
        "header_bg":   "#08101E",
        "header_text": "#DDE8F8",
        "accent":      "#5D9EFF",
        "accent_text": "#08101E",
        "body_text":   "#DDE8F8",
        "muted":       "#728EAF",
        "border":      "#142040",
        "link":        "#08101E",
        "cta_bg":      "#5D9EFF",
        "cta_text":    "#08101E",
    },

    # ── 4. LIGHT ──────────────────────────────────────────────────────────
    # bg:#F4F5F7  paper:#FFFFFF  primary:#1B5FFF  text:#0B1220
    # MuiCard: shadow only, no border — using alpha(#0B1220,0.08) → #DDE2EA
    "light": {
        "bg":          "#F4F5F7",
        "surface":     "#FFFFFF",
        "header_bg":   "#0B1220",
        "header_text": "#F4F5F7",
        "accent":      "#1B5FFF",
        "accent_text": "#FFFFFF",
        "body_text":   "#0B1220",
        "muted":       "#5A6677",
        "border":      "#DDE2EA",
        "link":        "#FFFFFF",
        "cta_bg":      "#1B5FFF",
        "cta_text":    "#FFFFFF",
    },

    # ── 5. PAPER ──────────────────────────────────────────────────────────
    # bg:#F0EDE7  paper:#FDFBF8  primary:#0F4CFF  text:#111827
    # MuiCard border: alpha(#111827,0.10) on cream → #E0DAD0
    "paper": {
        "bg":          "#F0EDE7",
        "surface":     "#FDFBF8",
        "header_bg":   "#2D2926",
        "header_text": "#FAF7F2",
        "accent":      "#0F4CFF",
        "accent_text": "#FFFFFF",
        "body_text":   "#111827",
        "muted":       "#6B7280",
        "border":      "#E0DAD0",
        "link":        "#FFFFFF",
        "cta_bg":      "#0F4CFF",
        "cta_text":    "#FFFFFF",
    },

    # ── 6. HIGH CONTRAST ─────────────────────────────────────────────────
    # bg:#000000  paper:#080808  primary:#FFFFFF  text:#FFFFFF
    # MuiPaper/Card border: 2px solid rgba(255,255,255,.88) → #E0E0E0 approx
    "high_contrast": {
        "bg":          "#000000",
        "surface":     "#080808",
        "header_bg":   "#000000",
        "header_text": "#FFFFFF",
        "accent":      "#FFFFFF",
        "accent_text": "#000000",
        "body_text":   "#FFFFFF",
        "muted":       "#AAAAAA",
        "border":      "#E0E0E0",
        "link":        "#000000",
        "cta_bg":      "#FFFFFF",
        "cta_text":    "#000000",
    },

    # ── 7. SUNRISE ────────────────────────────────────────────────────────
    # bg:#FFF5F0  paper:#FFFFFF  primary:#F03D2F  secondary:#FF8C00  text:#1A1A2E
    # Contained button: gradient primary→secondary — use primary for email
    "sunrise": {
        "bg":          "#FFF5F0",
        "surface":     "#FFFFFF",
        "header_bg":   "#C4200F",
        "header_text": "#FFF5F0",
        "accent":      "#F03D2F",
        "accent_text": "#FFFFFF",
        "body_text":   "#1A1A2E",
        "muted":       "#7A5050",
        "border":      "#FFD5CC",
        "link":        "#FFFFFF",
        "cta_bg":      "#F03D2F",
        "cta_text":    "#FFFFFF",
    },

    # ── 8. VALENTINE ─────────────────────────────────────────────────────
    # bg:#FFF0F4  paper:#FFFFFF  primary:#C2185B  secondary:#E91E8C  text:#1A0814
    # MuiCard border: alpha(#C2185B,0.12) on white → #FCCDD8
    "valentine": {
        "bg":          "#FFF0F4",
        "surface":     "#FFFFFF",
        "header_bg":   "#9F1239",
        "header_text": "#FFE4E6",
        "accent":      "#C2185B",
        "accent_text": "#FFFFFF",
        "body_text":   "#1A0814",
        "muted":       "#7A3050",
        "border":      "#FCCDD8",
        "link":        "#FFFFFF",
        "cta_bg":      "#C2185B",
        "cta_text":    "#FFFFFF",
    },

    # ── 9. CYBER ─────────────────────────────────────────────────────────
    # bg:#020408  paper:#06090F  primary:#00E5FF  secondary:#FF00CC  text:#E8F4FF
    # MuiPaper border: alpha(#00E5FF,0.18) on #020408 → #002933
    "cyber": {
        "bg":          "#020408",
        "surface":     "#06090F",
        "header_bg":   "#020408",
        "header_text": "#E8F4FF",
        "accent":      "#00E5FF",
        "accent_text": "#000000",
        "body_text":   "#E8F4FF",
        "muted":       "#6A8FA0",
        "border":      "#002933",
        "link":        "#000000",
        "cta_bg":      "#00E5FF",
        "cta_text":    "#000000",
    },

    # ── 10. THE ONE ───────────────────────────────────────────────────────
    # bg:#060606  paper:#0D0D0D  primary:#C9A84C  secondary:#E8D5A3  text:#F0ECD8
    # MuiPaper border: alpha(#C9A84C,0.16) on #060606 → #201A0A
    "the_one": {
        "bg":          "#060606",
        "surface":     "#0D0D0D",
        "header_bg":   "#060606",
        "header_text": "#F0ECD8",
        "accent":      "#C9A84C",
        "accent_text": "#060606",
        "body_text":   "#F0ECD8",
        "muted":       "#8C7E60",
        "border":      "#201A0A",
        "link":        "#060606",
        "cta_bg":      "#C9A84C",
        "cta_text":    "#060606",
    },

    # ── 11. METAL ─────────────────────────────────────────────────────────
    # bg:#06080C  paper:#0A0F15  primary:#E1061B  secondary:#EDEDED  text:#EDEDED
    # MuiPaper border: alpha(#EDEDED,0.10) on #06080C → #1A1D22
    # Link uses info colour #37D6C7 — more legible on dark than red
    "metal": {
        "bg":          "#06080C",
        "surface":     "#0A0F15",
        "header_bg":   "#06080C",
        "header_text": "#EDEDED",
        "accent":      "#E1061B",
        "accent_text": "#FFFFFF",
        "body_text":   "#EDEDED",
        "muted":       "#7A8090",
        "border":      "#1A1D22",
        "link":        "#FFFFFF",
        "cta_bg":      "#E1061B",
        "cta_text":    "#FFFFFF",
    },

    # ── 12. WINTER ────────────────────────────────────────────────────────
    # bg:#04080F  paper:#08122A  primary:#7DD3FC  secondary:#A5B4FC  text:#E8F2FF
    # MuiPaper border: alpha(#7DD3FC,0.14) on #04080F → #0C1C36
    "winter": {
        "bg":          "#04080F",
        "surface":     "#08122A",
        "header_bg":   "#04080F",
        "header_text": "#E8F2FF",
        "accent":      "#7DD3FC",
        "accent_text": "#04080F",
        "body_text":   "#E8F2FF",
        "muted":       "#6A8AAA",
        "border":      "#0C1C36",
        "link":        "#04080F",
        "cta_bg":      "#7DD3FC",
        "cta_text":    "#04080F",
    },

    # ── 13. SPRING ────────────────────────────────────────────────────────
    # bg:#F2FFF5  paper:#FFFFFF  primary:#15803D  secondary:#5B21B6  text:#0B1A10
    # No explicit card border; alpha(#15803D,0.14) on white → #C6EED4
    "spring": {
        "bg":          "#F2FFF5",
        "surface":     "#FFFFFF",
        "header_bg":   "#0B4D27",
        "header_text": "#F2FFF5",
        "accent":      "#15803D",
        "accent_text": "#FFFFFF",
        "body_text":   "#0B1A10",
        "muted":       "#4D7060",
        "border":      "#C6EED4",
        "link":        "#FFFFFF",
        "cta_bg":      "#15803D",
        "cta_text":    "#FFFFFF",
    },

    # ── 14. SUMMER ────────────────────────────────────────────────────────
    # bg:#FFFBEA  paper:#FFFFFF  primary:#D97706  secondary:#DC2626  text:#1A1000
    # alpha(#D97706,0.14) on white → #FDECC4
    "summer": {
        "bg":          "#FFFBEA",
        "surface":     "#FFFFFF",
        "header_bg":   "#92400E",
        "header_text": "#FFFBEA",
        "accent":      "#D97706",
        "accent_text": "#FFFFFF",
        "body_text":   "#1A1000",
        "muted":       "#7A5020",
        "border":      "#FDECC4",
        "link":        "#FFFFFF",
        "cta_bg":      "#D97706",
        "cta_text":    "#FFFFFF",
    },

    # ── 15. AUTUMN ────────────────────────────────────────────────────────
    # bg:#0C0805  paper:#170D09  primary:#F97316  secondary:#EAB308  text:#F5EDE0
    # MuiPaper border: alpha(#F97316,0.14) on #0C0805 → #211008
    "autumn": {
        "bg":          "#0C0805",
        "surface":     "#170D09",
        "header_bg":   "#0C0805",
        "header_text": "#F5EDE0",
        "accent":      "#F97316",
        "accent_text": "#0C0805",
        "body_text":   "#F5EDE0",
        "muted":       "#8A7060",
        "border":      "#211008",
        "link":        "#0C0805",
        "cta_bg":      "#F97316",
        "cta_text":    "#0C0805",
    },

    # ── 16. FUTURE ────────────────────────────────────────────────────────
    # bg:#0D0905  paper:#160E08  primary:#E8720C  secondary:#4A90D9  text:#E8DED0
    # MuiCard border: alpha(#E8720C,0.20) on #0D0905 → #2A1A0C
    # Top rule gradient amber→blue; links use Brigade blue #4A90D9
    "future": {
        "bg":          "#0D0905",
        "surface":     "#160E08",
        "header_bg":   "#0D0905",
        "header_text": "#E8DED0",
        "accent":      "#E8720C",
        "accent_text": "#0D0905",
        "body_text":   "#E8DED0",
        "muted":       "#7A6E60",
        "border":      "#2A1A0C",
        "link":        "#0D0905",
        "cta_bg":      "#E8720C",
        "cta_text":    "#0D0905",
    },
}

# Fall back to graphite when the theme value is missing or unrecognised
_DEFAULT_PALETTE = THEME_PALETTES["graphite"]


# ---------------------------------------------------------------------------
# Semantic color resolver
# ---------------------------------------------------------------------------

def _hex(color_entry: Any) -> str | None:
    """Extract hex from {"main": "#FF0000"} or a bare "#FF0000" string."""
    if isinstance(color_entry, dict):
        return color_entry.get("main")
    if isinstance(color_entry, str) and color_entry.startswith("#"):
        return color_entry
    return None


def resolve_semantic_colors(profile) -> dict[str, str]:
    """
    Return a flat dict of the user's semantic colors merged with defaults.

    Falls back to DEFAULT_SEMANTIC_COLORS from profiles.models when the
    profile is None or a key is absent.
    """
    from profiles.models import DEFAULT_SEMANTIC_COLORS
    import copy

    base = (
        profile.get_semantic_colors()
        if profile is not None
        else copy.deepcopy(DEFAULT_SEMANTIC_COLORS)
    )

    r = base.get("result", {})
    s = base.get("status", {})

    return {
        "color_safe":         _hex(r.get("safe"))         or "#22C55E",
        "color_suspicious":   _hex(r.get("suspicious"))   or "#F59E0B",
        "color_dangerous":    _hex(r.get("dangerous"))    or "#EF4444",
        "color_inconclusive": _hex(r.get("inconclusive")) or "#94A3B8",
        "color_done":         _hex(s.get("done"))         or "#22C55E",
        "color_in_progress":  _hex(s.get("in_progress"))  or "#3B82F6",
        "color_new":          _hex(s.get("new"))          or "#94A3B8",
        "color_failure":      _hex(s.get("failure"))      or "#EF4444",
        "color_challenged":   _hex(s.get("challenged"))   or "#A855F7",
        "color_unknown":      _hex(s.get("unknown"))      or "#64748B",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_email_theme(profile) -> dict[str, str]:
    """
    Given a UserProfile (or None), return a merged context dict ready for
    Jinja2 template.render(**ctx):

    Palette keys:
        bg, surface, header_bg, header_text, accent, accent_text,
        body_text, muted, border, link, cta_bg, cta_text

    Semantic keys:
        color_safe, color_dangerous, color_suspicious, color_inconclusive,
        color_done, color_in_progress, color_new, color_failure,
        color_challenged, color_unknown
    """
    theme_name: str = getattr(profile, "theme", "graphite") or "graphite"
    palette = THEME_PALETTES.get(theme_name, _DEFAULT_PALETTE).copy()
    semantic = resolve_semantic_colors(profile)
    return {**palette, **semantic}