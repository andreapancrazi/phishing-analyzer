"""HTML sanitization for the safe-mode email renderer.

Phishing emails routinely embed remote images ("tracking pixels") and other
remote resources. If the renderer fetches them, the sender can learn that the
email was opened and from what network — a real risk for an analyst working a
live sample. This module strips those references before the HTML ever reaches
the renderer, so blocking doesn't depend on what the underlying HTML widget
supports.
"""

import re

_SCRIPT_LIKE_RE = re.compile(
    r'<(script|iframe|object|embed)\b[^>]*>.*?</\1\s*>',
    re.DOTALL | re.IGNORECASE,
)
_SELF_CLOSING_LIKE_RE = re.compile(
    r'<(iframe|object|embed)\b[^>]*/?>',
    re.IGNORECASE,
)
_META_REFRESH_RE = re.compile(
    r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*>',
    re.IGNORECASE,
)
_FORM_ACTION_RE = re.compile(r'(<form\b[^>]*)\baction\s*=\s*(".*?"|\'.*?\')', re.IGNORECASE)

_IMG_TAG_RE = re.compile(r'<img\b[^>]*>', re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r'\bsrc\s*=\s*(".*?"|\'.*?\')', re.IGNORECASE)
_ALT_ATTR_RE = re.compile(r'\balt\s*=\s*(".*?"|\'.*?\')', re.IGNORECASE)

_LINK_STYLESHEET_RE = re.compile(
    r'<link\b(?=[^>]*rel\s*=\s*["\']?stylesheet)(?=[^>]*href\s*=\s*["\']?(?:https?:)?//)[^>]*>',
    re.IGNORECASE,
)
_CSS_URL_RE = re.compile(r'url\(\s*["\']?(?:https?:)?//[^)]*\)', re.IGNORECASE)

_REMOTE_SRC_RE = re.compile(r'^["\']?(?:https?:)?//', re.IGNORECASE)
_DATA_URI_SRC_RE = re.compile(r'^["\']?data:', re.IGNORECASE)

_CSS_IMPORTANT_RE = re.compile(r'\s*!\s*important', re.IGNORECASE)
_CSS_RGB_FUNC_RE = re.compile(
    r'rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*[\d.]+\s*)?\)',
    re.IGNORECASE,
)

_PLACEHOLDER_IMG = (
    'data:image/svg+xml;utf8,'
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">'
    '<rect width="24" height="24" fill="%23cccccc"/></svg>'
)


def _is_remote(src_value):
    """src_value includes surrounding quotes, e.g. '"https://x"'."""
    return bool(_REMOTE_SRC_RE.match(src_value.strip()))


def _is_data_uri(src_value):
    return bool(_DATA_URI_SRC_RE.match(src_value.strip()))


def _rgb_func_to_hex(m):
    r, g, b = (max(0, min(255, int(x))) for x in m.groups())
    return f'#{r:02x}{g:02x}{b:02x}'


def sanitize_html(html_src, allow_remote=False):
    """Strip active/remote content from an email's HTML body.

    Returns (clean_html, blocked_count). When allow_remote is True, remote
    images/stylesheets are left intact (still no scripts/iframes/forms —
    those aren't relevant to a legitimate email body anyway).

    Any <img src> that is neither a data: URI nor a remote http(s) URL is
    always stripped, regardless of allow_remote. The rendering widget treats
    an unrecognized src as a local filesystem path and will happily open it
    with PIL — an attacker-crafted email body must never be able to make the
    renderer read a file off the analyst's disk.
    """
    if not html_src:
        return html_src, 0

    blocked = 0
    text = _SCRIPT_LIKE_RE.sub(" ", html_src)
    text = _SELF_CLOSING_LIKE_RE.sub(" ", text)
    text = _META_REFRESH_RE.sub(" ", text)
    text = _FORM_ACTION_RE.sub(r'\1action="#"', text)

    def _img_sub(m):
        nonlocal blocked
        tag = m.group(0)
        src_m = _SRC_ATTR_RE.search(tag)
        if not src_m:
            return tag
        src_val = src_m.group(1)
        if _is_data_uri(src_val):
            return tag
        remote = _is_remote(src_val)
        if remote and allow_remote:
            return tag
        blocked += 1
        alt_m = _ALT_ATTR_RE.search(tag)
        alt = alt_m.group(0) if alt_m else ""
        # Single-quoted: the placeholder is an inline SVG data URI that itself
        # contains double quotes, which would otherwise terminate the attribute early.
        return f"<img src='{_PLACEHOLDER_IMG}' {alt}>"

    text = _IMG_TAG_RE.sub(_img_sub, text)

    if not allow_remote:
        def _link_sub(m):
            nonlocal blocked
            blocked += 1
            return " "

        text = _LINK_STYLESHEET_RE.sub(_link_sub, text)

        def _css_url_sub(m):
            nonlocal blocked
            blocked += 1
            return "none"

        text = _CSS_URL_RE.sub(_css_url_sub, text)

    # tkhtmlview's text-node handling collapses '\n'/'\t' to a space (per HTML
    # whitespace rules) but not bare '\r' — common in Outlook-authored HTML —
    # which then renders as a literal, glyph-less control character ("tofu
    # boxes") instead of collapsing away. Normalize before it reaches the
    # widget. Only affects the Rendered pane; HTML/Source tabs stay raw.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # tkhtmlview's CSS handling passes property values straight to Tk's color
    # parser. A bare "!important" suffix (common in real-world HTML emails)
    # makes Tk raise TclError and abort the render entirely, silently
    # bouncing the viewer to the plain-text fallback. Tk has no concept of
    # CSS specificity anyway, so the qualifier is meaningless here.
    text = _CSS_IMPORTANT_RE.sub("", text)

    # Same story for rgb()/rgba() — Tk's color parser only understands
    # #RRGGBB / named colors, not CSS's rgb() function syntax, and
    # tkhtmlview never converts it. Convert here (dropping alpha, which Tk
    # tag colors don't support) instead of letting the whole render abort.
    text = _CSS_RGB_FUNC_RE.sub(_rgb_func_to_hex, text)

    return text, blocked
