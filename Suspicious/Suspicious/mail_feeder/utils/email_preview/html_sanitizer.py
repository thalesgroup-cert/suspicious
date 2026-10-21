"""Allow-list sanitiser for the HTML body of a reported email.

The body is attacker-controlled and is rasterised by wkhtmltoimage on a
worker that can reach internal services, so anything that makes the
renderer fetch a URL (img/iframe/link/object, CSS url()/@import, meta
refresh, background attributes) must not survive. Everything not listed
here is dropped, rather than matching known-bad patterns.
"""
from __future__ import annotations

import re

import nh3

ALLOWED_TAGS = frozenset({
    "a", "abbr", "b", "blockquote", "br", "caption", "center", "cite", "code",
    "col", "colgroup", "dd", "del", "div", "dl", "dt", "em", "font", "h1", "h2",
    "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd", "li", "ol", "p",
    "pre", "q", "s", "small", "span", "strike", "strong", "sub", "sup", "table",
    "tbody", "td", "tfoot", "th", "thead", "tr", "tt", "u", "ul",
})

# Tags whose content is removed together with the tag (nh3 would otherwise
# keep the inner text, e.g. a stylesheet or an <iframe> fallback).
_DROP_WITH_CONTENT = {
    "script", "style", "head", "title", "iframe", "object", "embed", "svg",
    "math", "noscript", "template", "xmp", "textarea", "select", "option",
}

_ATTRIBUTES = {
    "*": {
        "align", "valign", "width", "height", "bgcolor", "color", "face", "size",
        "colspan", "rowspan", "border", "cellpadding", "cellspacing", "dir",
        "lang", "title", "class", "style",
    },
    "img": {"src", "alt"},
}

# Only declarations that cannot fetch anything. nh3 drops the rest of a
# style="" attribute (background, list-style-image, cursor, content, ...).
_STYLE_PROPERTIES = {
    "color", "background-color", "font", "font-family", "font-size",
    "font-style", "font-weight", "text-align", "text-decoration",
    "text-transform", "line-height", "letter-spacing", "vertical-align",
    "white-space", "word-break", "width", "height", "max-width", "min-width",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "border", "border-top", "border-right", "border-bottom", "border-left",
    "border-collapse", "border-spacing", "border-color", "border-style",
    "border-width", "border-radius", "display",
}

# Raster data: and cid: only. data:image/svg+xml can carry external refs.
_INLINE_IMAGE = re.compile(
    r"^(?:data:image/(?:png|jpe?g|gif|webp|bmp)[;,]|cid:)", re.IGNORECASE
)
# A <style> block is kept only if none of this appears (checked after
# comments are removed). Fail closed: any @-rule except @media, any backslash
# escape and any function or keyword that can load a resource or run code
# rejects the whole block. Plain words such as a ".image-wrap" class are fine
# because a fetch needs url(, image-set(, image(, ... or an @-rule.
_CSS_FORBIDDEN = re.compile(
    r"url|src\(|image-set|image\(|cross-fade|element\(|paint\(|import|expression|"
    r"behavior|binding|@(?!media\b)|[\\<&]|"
    # Layout tricks that could hide or cover the analyst header rows above the body.
    r"position|z-index|visibility|opacity|transform|float|display\s*:\s*none",
    re.IGNORECASE,
)

# Input beyond this is cut off before parsing; a mail body that large is not
# a legitimate preview and every pass below stays linear in it.
MAX_HTML_CHARS = 1024 * 1024

# nh3 is quadratic in nesting depth (20k nested <div> take about a second), so
# the number of tag openers is capped too. Real mail stays far below this.
MAX_HTML_TAGS = 10_000
# nh3 is also quadratic in the number of attributes on one tag (100k distinct
# attributes take about 12 s), so a single tag is capped as well.
MAX_TAG_CHARS = 20_000

_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def _attribute_filter(tag: str, attr: str, value: str):
    if attr == "src":
        return value if _INLINE_IMAGE.match(value.strip()) else None
    if attr == "style" and _CSS_FORBIDDEN.search(value):
        return None
    return value


_CLEANER = nh3.Cleaner(
    tags=set(ALLOWED_TAGS),
    clean_content_tags=_DROP_WITH_CONTENT,
    attributes=_ATTRIBUTES,
    attribute_filter=_attribute_filter,
    filter_style_properties=_STYLE_PROPERTIES,
    url_schemes={"data", "cid"},
    url_relative="deny",
    strip_comments=True,
    link_rel=None,
)


def _strip_css_comments(css: str) -> str:
    # Linear scan; an unterminated comment runs to the end, as in a browser.
    out, pos = [], 0
    while True:
        start = css.find("/*", pos)
        if start < 0:
            out.append(css[pos:])
            return "".join(out)
        out.append(css[pos:start])
        end = css.find("*/", start + 2)
        if end < 0:
            return "".join(out)
        pos = end + 2


def _style_block_bodies(html: str):
    # str.find based so each position is scanned once. When a needle is
    # missing it is missing for the rest of the input too, so stop.
    low = html.translate(_ASCII_LOWER)  # same length as html
    pos = 0
    while True:
        start = low.find("<style", pos)
        if start < 0:
            return
        after = start + len("<style")
        if after < len(low) and (low[after].isalnum() or low[after] in "-_"):
            pos = after
            continue
        open_end = low.find(">", after)
        if open_end < 0:
            return
        close = low.find("</style", open_end + 1)
        if close < 0:
            return
        close_end = low.find(">", close)
        if close_end < 0:
            return
        yield html[open_end + 1:close]
        pos = close_end + 1


def _safe_style_blocks(html: str) -> str:
    blocks = []
    for css in _style_block_bodies(html):
        css = _strip_css_comments(css)
        if css.strip() and not _CSS_FORBIDDEN.search(css):
            blocks.append(f"<style>{css}</style>")
    return "".join(blocks)


def _truncate(html: str) -> str:
    """Cut the body at the first sign of an input that makes nh3 slow."""
    html = html[:MAX_HTML_CHARS]
    pos = -1
    for _ in range(MAX_HTML_TAGS):
        pos = html.find("<", pos + 1)
        if pos < 0:
            return html
        end = html.find(">", pos)
        if end < 0 or end - pos > MAX_TAG_CHARS:
            return html[:pos]
    return html[:pos]


def sanitize_email_html(html: str) -> str:
    """Return ``html`` reduced to a fetch-free subset.

    <style> blocks are re-emitted separately because nh3 cannot inspect CSS:
    each one is checked by ``_CSS_FORBIDDEN`` and re-wrapped from the checked
    text, so nothing the HTML parser disagrees about can leak through.
    """
    html = _truncate(html).replace("\x00", "")
    return _safe_style_blocks(html) + _CLEANER.clean(html)
