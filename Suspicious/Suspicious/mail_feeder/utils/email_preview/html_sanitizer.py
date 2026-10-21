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
    "border-width", "border-radius", "display", "float",
}

# Raster data: and cid: only. data:image/svg+xml can carry external refs.
_INLINE_IMAGE = re.compile(
    r"^(?:data:image/(?:png|jpe?g|gif|webp|bmp)[;,]|cid:)", re.IGNORECASE
)
_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
# A <style> block is kept only if none of this appears (checked after
# comments are removed). Any @-rule except @media, any backslash escape and
# any function or keyword that can load a resource rejects the whole block.
_CSS_FORBIDDEN = re.compile(
    r"url|image|src|import|expression|behavior|binding|@(?!media\b)|[\\<&]",
    re.IGNORECASE,
)


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


def _safe_style_blocks(html: str) -> str:
    blocks = []
    for css in _STYLE_BLOCK.findall(html):
        css = _CSS_COMMENT.sub("", css)
        if css.strip() and not _CSS_FORBIDDEN.search(css):
            blocks.append(f"<style>{css}</style>")
    return "".join(blocks)


def sanitize_email_html(html: str) -> str:
    """Return ``html`` reduced to a fetch-free subset.

    <style> blocks are re-emitted separately because nh3 cannot inspect CSS:
    each one is checked by ``_CSS_FORBIDDEN`` and re-wrapped from the checked
    text, so nothing the HTML parser disagrees about can leak through.
    """
    html = html.replace("\x00", "")
    return _safe_style_blocks(html) + _CLEANER.clean(html)
