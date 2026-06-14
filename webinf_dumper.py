#!/usr/bin/env python3
"""
WEB-INF Dumper / Scanner.

Purpose:
    Recursively collect exposed Java web application resources under WEB-INF,
    META-INF, or BOOT-INF by combining a focused wordlist, configuration parsing,
    class constant-pool extraction, and optional CFR decompilation.

Inputs:
    TARGET_URL, output directory, optional wordlist, proxy, headers, limits, and
    optional CFR jar path.

Outputs:
    raw downloads, decompiled Java, and reports under OUT_DIR.

Side effects:
    Performs GET requests only. It does not upload files, mutate server state,
    submit forms, brute-force IDs, or execute application action endpoints.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import difflib
import hashlib
import heapq
import html.parser
import json
import os
import posixpath
import random
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Iterator


VERSION = "1.0.0"
BANNER = rf"""
__        __ _____ ____       ___ _   _ _____
\ \      / /| ____| __ )     |_ _| \ | |  ___|
 \ \ /\ / / |  _| |  _ \ _____| ||  \| | |_
  \ V  V /  | |___| |_) |_____| || |\  |  _|
   \_/\_/   |_____|____/     |___|_| \_|_|   dumper

version {VERSION}
made by mick3y
"""


DEFAULT_HEADERS = {
    "Sec-Ch-Ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Accept-Language": "ko-KR,ko;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    # urllib does not transparently decode brotli; identity keeps saved bytes predictable.
    "Accept-Encoding": "identity",
    "Priority": "u=0, i",
    "Connection": "keep-alive",
}

CONFIG_KEYS = {
    "spring.config.import",
    "logging.config",
    "spring.messages.basename",
    "mybatis.config-location",
    "mybatis.mapper-locations",
    "mapperlocations",
    "mapper.locations",
    "sqlmapconfig",
    "sqlmapconfiglocation",
    "configlocation",
    "configlocations",
    "contextconfiglocation",
    "hibernate.config",
    "hibernate.ejb.cfgfile",
}

LOCATION_ATTRS = {
    "resource",
    "resources",
    "location",
    "locations",
    "value",
    "file",
    "path",
    "configlocation",
    "configlocations",
    "mapperlocation",
    "mapperlocations",
    "mappinglocation",
    "mappinglocations",
    "sqlmapconfig",
    "sqlmapconfiglocation",
    "p:location",
}

CLASS_TAGS = {"filter-class", "listener-class", "servlet-class", "exception-type"}
PARAM_TAGS = {"param-value", "env-entry-value", "value"}
REFERENCE_EXTENSIONS = (
    ".xml",
    ".properties",
    ".yml",
    ".yaml",
    ".jsp",
    ".jspx",
    ".vm",
    ".ftl",
    ".class",
    ".tld",
    ".sql",
    ".js",
    ".css",
    ".json",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
)
PARSE_TEXT_EXTS = {
    ".xml",
    ".properties",
    ".yml",
    ".yaml",
    ".jsp",
    ".jspx",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".java",
    ".tld",
    ".txt",
    ".conf",
    ".sql",
}
ACTION_EXTENSIONS = (".do", ".mc", ".action")
SKIP_SCHEMES = {"data", "mailto", "javascript", "tel", "about"}
LIB_CLASS_PREFIXES = (
    "java.",
    "javax.",
    "jakarta.",
    "sun.",
    "com.sun.",
    "org.springframework.",
    "org.apache.",
    "org.slf4j.",
    "org.w3c.",
    "org.xml.",
    "com.fasterxml.",
    "com.google.",
    "net.sf.",
    "org.hibernate.",
    "org.mybatis.",
    "com.ibatis.",
)
COMMON_VIEW_PREFIXES = ("/WEB-INF/views/", "/WEB-INF/jsp/", "/WEB-INF/pages/")
APPCTX_WILDCARD_EXPANSIONS = (
    "",
    "-common",
    "-datasource",
    "-security",
    "-service",
    "-ibatis",
    "-mybatis",
)


@dataclasses.dataclass(slots=True)
class Candidate:
    priority: int
    seq: int
    url: str
    norm_path: str
    source: str
    referrer: str
    depth: int
    raw_ref: str = ""


@dataclasses.dataclass(slots=True)
class InventoryItem:
    url: str
    path: str
    local_path: str
    status: int | None
    content_type: str
    size: int
    sha256: str
    source: str
    referrer: str
    depth: int
    downloaded: bool
    error_like: bool
    parsed: bool
    error: str = ""


@dataclasses.dataclass(slots=True)
class RefRecord:
    source_file: str
    source_type: str
    ref_type: str
    raw_ref: str
    normalized_path: str
    action: str


@dataclasses.dataclass(slots=True)
class ErrorFingerprint:
    status: int | None
    content_type: str
    size: int
    title: str
    full_hash: str
    prefix_hash: str
    normalized_text: str


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value and name.lower() in {"src", "href", "action", "data", "formaction"}:
                self.refs.add(value)


class WebInfScanner:
    def __init__(
        self,
        target_url: str,
        out_dir: Path,
        *,
        wordlist: Path,
        proxy: str | None,
        headers: dict[str, str],
        timeout: float,
        max_workers: int,
        max_depth: int,
        max_requests: int,
        no_bruteforce: bool,
        no_decompile: bool,
        cfr_jar: Path | None,
        allow_cross_host: bool,
        keep_error_like: bool,
        debug: bool,
    ) -> None:
        self.target_url = canonical_url(target_url)
        self.out_dir = out_dir
        self.raw_dir = out_dir / "raw"
        self.decompiled_dir = out_dir / "decompiled"
        self.reports_dir = out_dir / "reports"
        self.wordlist = wordlist
        self.proxy = proxy
        self.headers = headers
        self.timeout = timeout
        self.max_workers = max(1, max_workers)
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.no_bruteforce = no_bruteforce
        self.no_decompile = no_decompile
        self.cfr_jar = resolve_cfr_jar(cfr_jar)
        self.allow_cross_host = allow_cross_host
        self.keep_error_like = keep_error_like
        self.debug = debug

        parts = urllib.parse.urlsplit(self.target_url)
        self.scheme = parts.scheme
        self.netloc = parts.netloc
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.context_prefix = infer_context_prefix(parts.path)

        self.queue: list[tuple[int, int, Candidate]] = []
        self.seq = 0
        self.queued_urls: set[str] = set()
        self.tried_urls: set[str] = set()
        self.tried_paths: set[str] = set()
        self.seen_sha256: dict[str, str] = {}
        self.items: list[InventoryItem] = []
        self.refs: list[RefRecord] = []
        self.skipped: list[RefRecord] = []
        self.sensitive_keys: set[tuple[str, str]] = set()
        self.unresolved_dynamic: set[tuple[str, str]] = set()
        self.view_resolvers: list[tuple[str, str]] = []
        self.component_packages: set[str] = set()
        self.error_fingerprints: list[ErrorFingerprint] = []
        self.decompile_warned = False
        self.progress_line_active = False
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.ended_at = ""

    def run(self) -> int:
        self.prepare_dirs()
        self.build_error_fingerprints()
        self.seed_queue()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures: dict[concurrent.futures.Future[tuple[InventoryItem, bytes | None]], Candidate] = {}
            while self.queue or futures:
                while self.queue and len(futures) < self.max_workers:
                    if self.max_requests and len(self.tried_urls) >= self.max_requests:
                        break
                    candidate = self.pop_next_candidate()
                    if candidate is None:
                        break
                    futures[executor.submit(self.fetch_candidate, candidate)] = candidate

                if not futures:
                    break

                done, _ = concurrent.futures.wait(
                    futures, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in done:
                    futures.pop(future)
                    item, body = future.result()
                    self.items.append(item)
                    if item.downloaded and not item.error_like and body is not None:
                        item.parsed = self.parse_download(item, body)
                    processed = len(self.items)
                    if processed == 1 or processed % 10 == 0 or self.debug:
                        self.print_progress()

        self.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.write_reports()
        self.print_progress(force=True)
        return 0

    def pop_next_candidate(self) -> Candidate | None:
        while self.queue:
            _, _, candidate = heapq.heappop(self.queue)
            if candidate.url in self.tried_urls:
                continue
            if candidate.norm_path in self.tried_paths and not candidate.url.endswith("/"):
                continue
            self.tried_urls.add(candidate.url)
            self.tried_paths.add(candidate.norm_path)
            return candidate
        return None

    def prepare_dirs(self) -> None:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.decompiled_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def seed_queue(self) -> None:
        parts = urllib.parse.urlsplit(self.target_url)
        target_norm = self.url_to_norm_path(self.target_url)
        if not parts.path.endswith("/") or target_norm in {"/WEB-INF/", "/META-INF/", "/BOOT-INF/"}:
            self.enqueue_url(self.target_url, target_norm, "target", "", 0, 0, self.target_url)

        for path in ("/WEB-INF/web.xml", "/WEB-INF/", "/META-INF/MANIFEST.MF"):
            self.enqueue_path(path, "seed", "", 0, 0, path)

        if self.no_bruteforce:
            return
        if not self.wordlist.exists():
            print(f"[warn] wordlist not found, skipping: {self.wordlist}", file=sys.stderr)
            return
        count = 0
        for line in self.wordlist.read_text(encoding="utf-8", errors="replace").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            norm = normalize_candidate_path(entry)
            if not norm:
                continue
            self.enqueue_path(norm, "wordlist", "", 0, 9, entry)
            count += 1
        if self.debug:
            print(f"[debug] loaded {count} wordlist entries from {self.wordlist}", file=sys.stderr)

    def build_error_fingerprints(self) -> None:
        nonce = hashlib.sha256(f"{time.time()}:{random.random()}:{self.target_url}".encode()).hexdigest()[:16]
        probes = [
            f"/WEB-INF/__scanner_missing_{nonce}.xml",
            f"/__scanner_missing_{nonce}.class",
            f"/WEB-INF/classes/__scanner_missing_{nonce}.properties",
        ]
        for path in probes:
            url = self.path_to_url(path)
            status, content_type, body, _ = self.get_url(url)
            if body is None:
                continue
            self.error_fingerprints.append(make_error_fingerprint(status, content_type, body, nonce))
        if self.debug:
            print(f"[debug] error fingerprints: {len(self.error_fingerprints)}", file=sys.stderr)

    def enqueue_path(
        self,
        norm_path: str,
        source: str,
        referrer: str,
        depth: int,
        priority: int,
        raw_ref: str,
    ) -> bool:
        if depth > self.max_depth:
            self.record_ref(referrer, source, "path", raw_ref, norm_path, "skipped:max-depth")
            return False
        if is_action_endpoint(norm_path):
            self.record_ref(referrer, source, "endpoint", raw_ref, norm_path, "record-only:endpoint")
            return False
        url = self.path_to_url(norm_path)
        return self.enqueue_url(url, norm_path, source, referrer, depth, priority, raw_ref)

    def enqueue_url(
        self,
        url: str,
        norm_path: str,
        source: str,
        referrer: str,
        depth: int,
        priority: int,
        raw_ref: str,
    ) -> bool:
        url = canonical_url(url)
        if not self.allow_cross_host and urllib.parse.urlsplit(url).netloc != self.netloc:
            self.record_ref(referrer, source, "url", raw_ref, url, "skipped:external")
            return False
        if url in self.queued_urls or url in self.tried_urls:
            return False
        self.seq += 1
        self.queued_urls.add(url)
        heapq.heappush(
            self.queue,
            (priority, self.seq, Candidate(priority, self.seq, url, norm_path, source, referrer, depth, raw_ref)),
        )
        if raw_ref:
            self.record_ref(referrer, source, "path", raw_ref, norm_path, "queued")
        return True

    def fetch_candidate(self, candidate: Candidate) -> tuple[InventoryItem, bytes | None]:
        status, content_type, body, error = self.get_url(candidate.url)
        if body is None:
            return (
                InventoryItem(
                    url=candidate.url,
                    path=candidate.norm_path,
                    local_path="",
                    status=status,
                    content_type=content_type,
                    size=0,
                    sha256="",
                    source=candidate.source,
                    referrer=candidate.referrer,
                    depth=candidate.depth,
                    downloaded=False,
                    error_like=False,
                    parsed=False,
                    error=error,
                ),
                None,
            )

        digest = hashlib.sha256(body).hexdigest()
        error_like = self.is_error_like(status, content_type, body)
        downloaded = bool(status and 200 <= status < 300 and not error_like)
        local_path = ""
        if (downloaded or self.keep_error_like) and body:
            local = safe_join(self.raw_dir, candidate.norm_path.lstrip("/") or "index.html")
            if candidate.norm_path.endswith("/"):
                local = safe_join(self.raw_dir, candidate.norm_path.lstrip("/") + "index.html")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(body)
            local_path = str(local)
            if downloaded and digest not in self.seen_sha256:
                self.seen_sha256[digest] = local_path

        return (
            InventoryItem(
                url=candidate.url,
                path=candidate.norm_path,
                local_path=local_path,
                status=status,
                content_type=content_type,
                size=len(body),
                sha256=digest,
                source=candidate.source,
                referrer=candidate.referrer,
                depth=candidate.depth,
                downloaded=downloaded,
                error_like=error_like,
                parsed=False,
                error=error,
            ),
            body if downloaded else None,
        )

    def get_url(self, url: str) -> tuple[int | None, str, bytes | None, str]:
        opener = self.make_opener()
        request = urllib.request.Request(url, method="GET", headers=self.headers)
        try:
            with opener.open(request, timeout=self.timeout) as response:
                status = getattr(response, "status", None)
                content_type = response.headers.get("Content-Type", "")
                return status, content_type, response.read(), ""
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""
            return exc.code, exc.headers.get("Content-Type", ""), body, f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - network errors belong in the report.
            return None, "", None, f"{type(exc).__name__}: {exc}"

    def make_opener(self) -> urllib.request.OpenerDirector:
        if not self.proxy:
            return urllib.request.build_opener()
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy})
        )

    def is_error_like(self, status: int | None, content_type: str, body: bytes) -> bool:
        if status and status >= 400:
            return True
        if not body:
            return False
        current = make_error_fingerprint(status, content_type, body)
        for known in self.error_fingerprints:
            if current.full_hash == known.full_hash:
                return True
            if current.prefix_hash == known.prefix_hash and abs(current.size - known.size) < 80:
                return True
            if current.title and current.title == known.title and abs(current.size - known.size) < 512:
                return True
            if current.content_type.split(";")[0] == known.content_type.split(";")[0]:
                ratio = difflib.SequenceMatcher(None, current.normalized_text, known.normalized_text).ratio()
                if ratio >= 0.90 and abs(current.size - known.size) < max(1024, known.size // 3):
                    return True
        return looks_like_generic_error(status, content_type, body)

    def parse_download(self, item: InventoryItem, body: bytes) -> bool:
        ext = Path(item.path).suffix.lower()
        source_type = classify_source_type(item.path, item.content_type, body)
        refs: list[tuple[str, str, int]] = []
        text = ""
        if ext == ".class" or is_class_file(body):
            refs.extend((ref, "class-constant-pool", 2) for ref in extract_class_refs(body))
            self.maybe_decompile(item, body)
        else:
            text = decode_text(body)
            if source_type == "web.xml":
                refs.extend((ref, "web.xml", prio) for ref, prio in parse_web_xml(text, self))
            elif source_type in {"spring-xml", "mybatis", "hibernate", "xml"}:
                refs.extend((ref, source_type, prio) for ref, prio in parse_xml(text, source_type, self, item.path))
            elif source_type == "properties":
                refs.extend((ref, "properties", 0) for ref in parse_properties(text, item.path, self))
            elif source_type == "yaml":
                refs.extend((ref, "yaml", 0) for ref in parse_yaml(text, item.path, self))
            elif source_type in {"jsp", "html"}:
                refs.extend((ref, "jsp", 5) for ref in parse_html_jsp(text))
            elif source_type == "css":
                refs.extend((ref, "css", 5) for ref in parse_css(text))
            elif source_type == "js":
                refs.extend((ref, "js", 5) for ref in parse_js(text))
            elif source_type == "java":
                refs.extend((ref, "decompiled-java", prio) for ref, prio in parse_java(text, self, item.path))

        for raw_ref, ref_source, priority in refs:
            self.handle_raw_ref(raw_ref, item.path, ref_source, item.depth + 1, priority)
        return bool(refs) or source_type in {
            "web.xml",
            "spring-xml",
            "mybatis",
            "hibernate",
            "properties",
            "yaml",
            "jsp",
            "html",
            "css",
            "js",
            "java",
            "class",
        }

    def handle_raw_ref(
        self,
        raw_ref: str,
        source_path: str,
        source_type: str,
        depth: int,
        priority: int,
    ) -> None:
        for norm_path, action in normalize_ref(raw_ref, source_path, self.view_resolvers):
            if action.startswith("unresolved"):
                self.unresolved_dynamic.add((source_path, raw_ref))
                self.record_ref(source_path, source_type, "dynamic", raw_ref, norm_path, action)
                continue
            if action == "record-only:endpoint":
                self.record_ref(source_path, source_type, "endpoint", raw_ref, norm_path, action)
                continue
            if action.startswith("skipped"):
                self.record_ref(source_path, source_type, "path", raw_ref, norm_path, action)
                continue
            if norm_path.startswith(("http://", "https://")):
                parsed = urllib.parse.urlsplit(norm_path)
                normalized_path = self.url_to_norm_path(norm_path) if parsed.netloc == self.netloc else normalize_candidate_path(parsed.path)
                self.enqueue_url(norm_path, normalized_path, source_type, source_path, depth, priority, raw_ref)
                continue
            self.enqueue_path(norm_path, source_type, source_path, depth, priority, raw_ref)

    def maybe_decompile(self, item: InventoryItem, body: bytes) -> None:
        if self.no_decompile:
            return
        if not self.cfr_jar or not self.cfr_jar.exists() or not shutil.which("java"):
            if not self.decompile_warned:
                print(
                    "[warn] CFR decompilation unavailable; looked for cfr.jar in --cfr-jar, cwd, /tmp, /tmp/mobile2, and script-relative tools/",
                    file=sys.stderr,
                )
                self.decompile_warned = True
            return
        if not item.local_path:
            return
        try:
            subprocess.run(
                [
                    "java",
                    "-jar",
                    str(self.cfr_jar),
                    item.local_path,
                    "--outputdir",
                    str(self.decompiled_dir),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(20, int(self.timeout * 2)),
            )
        except Exception as exc:  # noqa: BLE001 - decompilation is optional.
            if self.debug:
                print(f"[debug] CFR failed for {item.path}: {exc}", file=sys.stderr)
            return
        class_name = Path(item.local_path).stem + ".java"
        for java_path in self.decompiled_dir.rglob(class_name):
            try:
                text = java_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = "/" + str(java_path.relative_to(self.decompiled_dir)).replace(os.sep, "/")
            for raw_ref, priority in parse_java(text, self, rel):
                self.handle_raw_ref(raw_ref, item.path, "decompiled-java", item.depth + 1, priority)

    def path_to_url(self, norm_path: str) -> str:
        norm_path = normalize_candidate_path(norm_path) or "/"
        path = norm_path
        if self.context_prefix and norm_path.startswith(("/WEB-INF", "/META-INF", "/BOOT-INF")):
            path = posixpath.join(self.context_prefix, norm_path.lstrip("/"))
        return urllib.parse.urlunsplit((self.scheme, self.netloc, path, "", ""))

    def url_to_norm_path(self, url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(parts.path) or "/"
        if self.context_prefix and path.startswith(self.context_prefix.rstrip("/") + "/"):
            path = path[len(self.context_prefix.rstrip("/")) :]
        if path in {"/WEB-INF", "/META-INF", "/BOOT-INF"}:
            return path + "/"
        if path.endswith("/") and path not in {"/WEB-INF/", "/META-INF/", "/BOOT-INF/"}:
            return path
        return normalize_candidate_path(path) or "/"

    def record_ref(
        self,
        source_file: str,
        source_type: str,
        ref_type: str,
        raw_ref: str,
        normalized_path: str,
        action: str,
    ) -> None:
        record = RefRecord(source_file, source_type, ref_type, raw_ref, normalized_path, action)
        self.refs.append(record)
        if action.startswith("skipped") or action.startswith("record-only"):
            self.skipped.append(record)

    def print_progress(self, *, force: bool = False) -> None:
        processed = len(self.tried_urls)
        discovered = len(self.queued_urls)
        if not force and discovered < 1:
            return
        downloaded = sum(1 for item in self.items if item.downloaded)
        failed = sum(1 for item in self.items if not item.downloaded and not item.error_like)
        queue = len(self.queue)
        error_like = sum(1 for item in self.items if item.error_like)
        pct = int((processed / discovered) * 100) if discovered else 100
        bar_width = 28
        filled = int((pct / 100) * bar_width)
        bar = "#" * filled + "-" * (bar_width - filled)
        line = (
            f"\r[{bar}] {pct:3d}% "
            f"processed={processed} discovered={discovered} "
            f"downloaded={downloaded} failed={failed} error_like={error_like} queue={queue}"
        )
        print(line, end="", file=sys.stderr, flush=True)
        self.progress_line_active = True
        if force:
            print(file=sys.stderr)
            self.progress_line_active = False

    def write_reports(self) -> None:
        inventory = [dataclasses.asdict(item) for item in self.items]
        counts = {
            "discovered": len(self.queued_urls),
            "attempted": len(self.tried_urls),
            "downloaded": sum(1 for item in self.items if item.downloaded),
            "failed": sum(1 for item in self.items if not item.downloaded and not item.error_like),
            "error_like": sum(1 for item in self.items if item.error_like),
            "skipped": len(self.skipped),
            "skipped_external": sum(1 for record in self.skipped if record.action == "skipped:external"),
        }
        payload = {
            "target_url": self.target_url,
            "context_prefix": self.context_prefix,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "counts": counts,
            "cfr_jar": str(self.cfr_jar) if self.cfr_jar else "",
            "items": inventory,
            "view_resolvers": [{"prefix": p, "suffix": s} for p, s in self.view_resolvers],
            "sensitive_keys": [
                {"file": path, "key": key} for path, key in sorted(self.sensitive_keys)
            ],
            "unresolved_dynamic_references": [
                {"file": path, "raw_ref": ref} for path, ref in sorted(self.unresolved_dynamic)
            ],
        }
        (self.reports_dir / "inventory.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        with (self.reports_dir / "fetch_log.tsv").open("w", encoding="utf-8") as fh:
            fh.write("timestamp\tmethod\turl\tstatus\tcontent_type\tsize\tsha256\terror_like\tsource\treferrer\tlocal_path\terror\n")
            for item in self.items:
                fh.write(
                    f"{self.ended_at or self.started_at}\tGET\t{item.url}\t{item.status or ''}\t"
                    f"{tsv(item.content_type)}\t{item.size}\t{item.sha256}\t{item.error_like}\t"
                    f"{tsv(item.source)}\t{tsv(item.referrer)}\t{tsv(item.local_path)}\t{tsv(item.error)}\n"
                )
        with (self.reports_dir / "discovered_refs.tsv").open("w", encoding="utf-8") as fh:
            fh.write("source_file\tsource_type\tref_type\traw_ref\tnormalized_path\taction\n")
            for record in self.refs:
                fh.write(
                    f"{tsv(record.source_file)}\t{tsv(record.source_type)}\t{tsv(record.ref_type)}\t"
                    f"{tsv(record.raw_ref)}\t{tsv(record.normalized_path)}\t{tsv(record.action)}\n"
                )
        with (self.reports_dir / "skipped.tsv").open("w", encoding="utf-8") as fh:
            fh.write("source_file\tsource_type\tref_type\traw_ref\tnormalized_path\taction\n")
            for record in self.skipped:
                fh.write(
                    f"{tsv(record.source_file)}\t{tsv(record.source_type)}\t{tsv(record.ref_type)}\t"
                    f"{tsv(record.raw_ref)}\t{tsv(record.normalized_path)}\t{tsv(record.action)}\n"
                )
        (self.reports_dir / "summary.md").write_text(render_summary(payload), encoding="utf-8")


def canonical_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("TARGET_URL must be an absolute http(s) URL")
    return urllib.parse.urlunsplit(parsed._replace(fragment=""))


def infer_context_prefix(path: str) -> str:
    for marker in ("/WEB-INF", "/META-INF", "/BOOT-INF"):
        idx = path.find(marker)
        if idx >= 0:
            return path[:idx] or ""
    return ""


def normalize_candidate_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if not value:
        return ""
    if "?" in value:
        value = value.split("?", 1)[0]
    if "#" in value:
        value = value.split("#", 1)[0]
    if value.startswith("WEB-INF/") or value == "WEB-INF":
        value = "/" + value
    if value.startswith("META-INF/") or value == "META-INF":
        value = "/" + value
    if value.startswith("BOOT-INF/") or value == "BOOT-INF":
        value = "/" + value
    if not value.startswith("/"):
        value = "/" + value
    trailing = value.endswith("/")
    norm = posixpath.normpath(value)
    if trailing and not norm.endswith("/"):
        norm += "/"
    if norm.startswith("/../"):
        return ""
    return norm


def safe_join(root: Path, rel_path: str) -> Path:
    root_resolved = root.resolve()
    path = (root / rel_path).resolve()
    if path != root_resolved and root_resolved not in path.parents:
        raise ValueError(f"unsafe output path: {rel_path}")
    return path


def decode_text(body: bytes) -> str:
    for encoding in ("utf-8", "cp949", "euc-kr", "latin-1"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def is_class_file(body: bytes) -> bool:
    return len(body) >= 4 and body[:4] == b"\xca\xfe\xba\xbe"


def classify_source_type(path: str, content_type: str, body: bytes) -> str:
    lower = path.lower()
    ext = Path(lower).suffix
    if lower.endswith("/web.xml") or lower == "/web.xml":
        return "web.xml"
    if ext == ".class" or is_class_file(body):
        return "class"
    if ext == ".properties":
        return "properties"
    if ext in {".yml", ".yaml"}:
        return "yaml"
    if ext in {".jsp", ".jspx"}:
        return "jsp"
    if ext in {".html", ".htm"} or "html" in content_type.lower():
        return "html"
    if ext == ".css":
        return "css"
    if ext == ".js":
        return "js"
    if ext == ".java":
        return "java"
    if ext == ".xml" or "xml" in content_type.lower():
        name = Path(lower).name
        if name in {"mybatis-config.xml", "sql-map-config.xml", "sqlmap-config.xml", "sqlmapconfig.xml"}:
            return "mybatis"
        if name in {"hibernate.cfg.xml", "persistence.xml"}:
            return "hibernate"
        text = decode_text(body[:20000])
        if "springframework.org/schema" in text or "<beans" in text:
            return "spring-xml"
        if "<sqlmap" in text.lower() or "<mapper" in text.lower():
            return "mybatis"
        if "<hibernate-configuration" in text.lower() or "<persistence" in text.lower():
            return "hibernate"
        return "xml"
    return "binary"


def make_error_fingerprint(
    status: int | None,
    content_type: str,
    body: bytes,
    nonce: str | None = None,
) -> ErrorFingerprint:
    text = decode_text(body[:65536])
    if nonce:
        text = text.replace(nonce, "*")
    title_match = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", text, re.I | re.S)
    title = normalize_text(title_match.group(1)) if title_match else ""
    normalized = normalize_error_text(text)
    return ErrorFingerprint(
        status=status,
        content_type=content_type.lower(),
        size=len(body),
        title=title,
        full_hash=hashlib.sha256(body).hexdigest(),
        prefix_hash=hashlib.sha256(body[:2048]).hexdigest(),
        normalized_text=normalized,
    )


def normalize_error_text(text: str) -> str:
    text = re.sub(r"__scanner_missing_[A-Za-z0-9]+", "__scanner_missing_*", text)
    text = re.sub(r"/(?:WEB-INF/|META-INF/|BOOT-INF/)?__scanner_missing_[^\s\"'<>]+", "/__scanner_missing_*", text)
    text = re.sub(r"https?://[^\s\"'<>]+", "URL", text)
    text = re.sub(r"/[A-Za-z0-9_./;?=&%+~,@!$()#*:-]+", "PATH", text)
    return normalize_text(text)[:12000]


def normalize_text(text: str) -> str:
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def looks_like_generic_error(status: int | None, content_type: str, body: bytes) -> bool:
    if status and status >= 400:
        return True
    if len(body) > 65536 or "html" not in content_type.lower():
        return False
    text = normalize_text(decode_text(body[:65536]))
    indicators = (
        "404",
        "not found",
        "forbidden",
        "access denied",
        "error occurred",
        "요청하신 페이지",
        "페이지를 찾을 수",
        "접근 권한",
    )
    return any(indicator in text for indicator in indicators)


def parse_web_xml(text: str, scanner: WebInfScanner) -> list[tuple[str, int]]:
    refs = parse_xml(text, "web.xml", scanner, "/WEB-INF/web.xml")
    return refs


def parse_xml(
    text: str,
    source_type: str,
    scanner: WebInfScanner,
    source_path: str,
) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except Exception:
        return parse_xml_regex(text, source_type)

    for elem in root.iter():
        lname = local_name(elem.tag).lower()
        value = (elem.text or "").strip()
        if lname in CLASS_TAGS and value:
            refs.append((class_name_to_path(value), 1))
        elif lname == "servlet-name" and value:
            refs.append((f"/WEB-INF/{value}-servlet.xml", 0))
        elif lname in PARAM_TAGS and is_reference_candidate(value):
            refs.extend((piece, 0) for piece in split_ref_values(value))
        elif source_type == "hibernate" and lname == "class" and looks_like_java_class(value):
            refs.append((class_name_to_path(value), 1))

        attrs = {local_name(k).lower(): v.strip() for k, v in elem.attrib.items() if v and v.strip()}
        if lname == "bean" and "class" in attrs:
            refs.append((class_name_to_path(attrs["class"]), 1))
        if lname == "component-scan" and "base-package" in attrs:
            for package_name in re.split(r"[,;\s]+", attrs["base-package"]):
                if looks_like_java_package(package_name):
                    scanner.component_packages.add(package_name)
                    scanner.record_ref(source_path, source_type, "package-hint", package_name, package_name, "record-only:package-hint")
                    if package_name.endswith(".controller"):
                        refs.append((class_name_to_path(package_name + ".MainController"), 1))
        if lname in {"sqlmap", "mapper"}:
            if "resource" in attrs:
                resource = attrs["resource"].lstrip("/")
                refs.append(("classpath:" + resource, 0))
                refs.extend((candidate, 1) for candidate in sqlmap_class_candidates(resource, scanner))
            if "url" in attrs:
                scanner.record_ref(source_path, source_type, "url", attrs["url"], attrs["url"], "record-only:file-url")
        if lname == "package" and "name" in attrs:
            scanner.record_ref(source_path, source_type, "package-hint", attrs["name"], attrs["name"], "record-only:package-hint")
        if lname == "mapping":
            if "resource" in attrs:
                refs.append(("classpath:" + attrs["resource"].lstrip("/"), 0))
            if "class" in attrs:
                refs.append((class_name_to_path(attrs["class"]), 1))

        for raw_attr, attr_value in elem.attrib.items():
            attr_name = local_name(raw_attr).lower()
            if attr_name in LOCATION_ATTRS or "location" in attr_name:
                refs.extend((piece, 0) for piece in split_ref_values(attr_value))
            elif attr_name in {"typealiasespackage", "base-package"}:
                scanner.record_ref(source_path, source_type, "package-hint", attr_value, attr_value, "record-only:package-hint")

    refs.extend(parse_xml_regex(text, source_type, scanner=scanner, source_path=source_path))
    scanner.view_resolvers.extend(extract_view_resolvers(root))
    return dedupe_pairs(refs)


def parse_xml_regex(
    text: str,
    source_type: str,
    scanner: WebInfScanner | None = None,
    source_path: str = "",
) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    for tag in CLASS_TAGS:
        for value in re.findall(rf"<(?:\w+:)?{tag}>\s*([^<]+?)\s*</", text, re.I):
            refs.append((class_name_to_path(value), 1))
    for value in re.findall(r"<(?:\w+:)?servlet-name>\s*([^<]+?)\s*</", text, re.I):
        value = value.strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
            refs.append((f"/WEB-INF/{value}-servlet.xml", 0))
    attr_re = re.compile(
        r"""(?:resource|location|locations|value|configLocation|configLocations|mapperLocations|mappingLocations|sqlMapConfigLocation)\s*=\s*["']([^"']+)["']""",
        re.I,
    )
    for value in attr_re.findall(text):
        refs.extend((piece, 0) for piece in split_ref_values(value))
        if scanner and re.search(r"(?:sqlmap|mapper).*\.xml$", value, re.I):
            refs.extend((candidate, 1) for candidate in sqlmap_class_candidates(value, scanner))
    for value in re.findall(r"<(?:\w+:)?(?:param-value|value|env-entry-value)>\s*([^<]+?)\s*</", text, re.I):
        if is_reference_candidate(value):
            refs.extend((piece, 0) for piece in split_ref_values(value))
    if scanner:
        for package_name in re.findall(r"""base-package\s*=\s*["']([^"']+)["']""", text, re.I):
            for piece in re.split(r"[,;\s]+", package_name):
                if looks_like_java_package(piece):
                    scanner.component_packages.add(piece)
                    scanner.record_ref(source_path, source_type, "package-hint", piece, piece, "record-only:package-hint")
                    if piece.endswith(".controller"):
                        refs.append((class_name_to_path(piece + ".MainController"), 1))
        for resource in re.findall(r"""<(?:\w+:)?sqlMap\b[^>]*\bresource\s*=\s*["']([^"']+)["']""", text, re.I):
            refs.extend((candidate, 1) for candidate in sqlmap_class_candidates(resource, scanner))
        for resource in re.findall(r"""<(?:\w+:)?mapper\b[^>]*\bresource\s*=\s*["']([^"']+)["']""", text, re.I):
            refs.extend((candidate, 1) for candidate in sqlmap_class_candidates(resource, scanner))
    return dedupe_pairs(refs)


def extract_view_resolvers(root: ET.Element) -> list[tuple[str, str]]:
    resolvers: list[tuple[str, str]] = []
    for bean in root.iter():
        if local_name(bean.tag).lower() != "bean":
            continue
        class_attr = next((v for k, v in bean.attrib.items() if local_name(k).lower() == "class"), "")
        if "InternalResourceViewResolver" not in class_attr:
            continue
        prefix = ""
        suffix = ""
        for child in list(bean):
            if local_name(child.tag).lower() != "property":
                continue
            name = child.attrib.get("name", "")
            value = child.attrib.get("value", "") or (child.text or "").strip()
            if name == "prefix":
                prefix = value
            elif name == "suffix":
                suffix = value
        if prefix and suffix:
            resolvers.append((prefix, suffix))
    return resolvers


def parse_properties(text: str, source_path: str, scanner: WebInfScanner) -> list[str]:
    refs: list[str] = []
    for key, value in iter_properties(text):
        key_lower = key.lower()
        if any(token in key_lower for token in ("password", "passwd", "secret", "token", "accesskey", "apikey", "private")):
            scanner.sensitive_keys.add((source_path, key))
        if key_lower in CONFIG_KEYS or is_reference_candidate(value):
            refs.extend(split_ref_values(value))
    return dedupe(refs)


def iter_properties(text: str) -> Iterator[tuple[str, str]]:
    logical = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not logical and (not line.strip() or line.lstrip().startswith(("#", "!"))):
            continue
        if line.endswith("\\"):
            logical += line[:-1]
            continue
        logical += line
        sep_match = re.search(r"(?<!\\)(=|:)", logical)
        if sep_match:
            key = logical[: sep_match.start()].strip()
            value = logical[sep_match.end() :].strip()
            yield key, value
        logical = ""


def parse_yaml(text: str, source_path: str, scanner: WebInfScanner) -> list[str]:
    refs: list[str] = []
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        for key_path, value in walk_yaml(data):
            key_lower = ".".join(key_path).lower()
            if any(token in key_lower for token in ("password", "passwd", "secret", "token", "accesskey", "apikey", "private")):
                scanner.sensitive_keys.add((source_path, ".".join(key_path)))
            if isinstance(value, str) and (key_lower in CONFIG_KEYS or is_reference_candidate(value)):
                refs.extend(split_ref_values(value))
    except Exception:
        for line in text.splitlines():
            if ":" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            key_lower = key.lower()
            if any(token in key_lower for token in ("password", "passwd", "secret", "token", "accesskey", "apikey", "private")):
                scanner.sensitive_keys.add((source_path, key))
            if key_lower in CONFIG_KEYS or is_reference_candidate(value):
                refs.extend(split_ref_values(value))
    return dedupe(refs)


def walk_yaml(data: object, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], object]]:
    if isinstance(data, dict):
        for key, value in data.items():
            yield from walk_yaml(value, prefix + (str(key),))
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            yield from walk_yaml(value, prefix + (str(idx),))
    else:
        yield prefix, data


def parse_html_jsp(text: str) -> list[str]:
    refs: set[str] = set()
    parser = LinkParser()
    try:
        parser.feed(text)
        refs.update(parser.refs)
    except Exception:
        pass
    refs.update(re.findall(r"""<%@\s*include\s+file\s*=\s*["']([^"']+)["']""", text, re.I))
    refs.update(re.findall(r"""<jsp:include\s+page\s*=\s*["']([^"']+)["']""", text, re.I))
    return sorted(refs)


def parse_css(text: str) -> list[str]:
    refs = set(re.findall(r"""url\(\s*["']?([^)"'\s]+)""", text, re.I))
    refs.update(re.findall(r"""@import\s+(?:url\()?["']([^"']+)["']""", text, re.I))
    return sorted(refs)


def parse_js(text: str) -> list[str]:
    refs: set[str] = set()
    for value in extract_string_literals(text):
        if value.lower().endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".xml", ".json", ".properties")):
            refs.add(value)
        elif is_action_endpoint(value):
            refs.add(value)
    return sorted(refs)


def parse_java(text: str, scanner: WebInfScanner, source_path: str) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    for value in extract_string_literals(text):
        if "${" in value or "<%=" in value:
            scanner.unresolved_dynamic.add((source_path, value))
            continue
        if is_reference_candidate(value):
            refs.append((value, 3))
        if value.startswith(("redirect:", "forward:")):
            scanner.record_ref(source_path, "decompiled-java", "endpoint", value, value, "record-only:endpoint")
    for class_name in re.findall(r"^import\s+((?:[a-z_][a-z0-9_]*\.)+[A-Z][A-Za-z0-9_$]*);", text, re.M):
        refs.append((class_name_to_path(class_name), 3))
    for class_name in re.findall(r"\b(?:[a-z_][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_$]*\b", text):
        refs.append((class_name_to_path(class_name), 3))
    for endpoint in re.findall(r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(([^)]*)\)", text):
        scanner.record_ref(source_path, "decompiled-java", "endpoint", endpoint, endpoint, "record-only:endpoint")
    for view in re.findall(r"""\.setViewName\s*\(\s*"([^"]+)"\s*\)""", text):
        refs.extend((candidate, 4) for candidate in view_name_candidates(view, scanner.view_resolvers, explicit=True))
    for view in re.findall(r"""new\s+ModelAndView\s*\(\s*"([^"]+)"\s*\)""", text):
        refs.extend((candidate, 4) for candidate in view_name_candidates(view, scanner.view_resolvers, explicit=True))
    if "Controller" in text or "@Controller" in text:
        for view in re.findall(r'return\s+"([^"]+)"', text):
            refs.extend((candidate, 4) for candidate in view_name_candidates(view, scanner.view_resolvers, explicit=False))
    return dedupe_pairs([(ref, prio) for ref, prio in refs if ref])


def extract_string_literals(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text):
        raw = match.group(1)
        try:
            values.append(bytes(raw, "utf-8").decode("unicode_escape"))
        except Exception:
            values.append(raw)
    return values


def extract_class_refs(body: bytes) -> list[str]:
    refs: set[str] = set()
    for value in parse_class_utf8_constants(body):
        if value.startswith("L") and value.endswith(";"):
            value = value[1:-1]
        if looks_like_jvm_class(value):
            refs.add(jvm_class_to_path(value))
        elif looks_like_java_class(value):
            refs.add(class_name_to_path(value))
        elif is_reference_candidate(value):
            refs.add(value)
    return sorted(ref for ref in refs if ref)


def parse_class_utf8_constants(body: bytes) -> list[str]:
    if len(body) < 10 or body[:4] != b"\xca\xfe\xba\xbe":
        return []
    try:
        cp_count = struct.unpack(">H", body[8:10])[0]
        offset = 10
        values: list[str] = []
        index = 1
        while index < cp_count and offset < len(body):
            tag = body[offset]
            offset += 1
            if tag == 1:
                length = struct.unpack(">H", body[offset : offset + 2])[0]
                offset += 2
                raw = body[offset : offset + length]
                offset += length
                values.append(raw.decode("utf-8", errors="replace"))
            elif tag in {3, 4}:
                offset += 4
            elif tag in {5, 6}:
                offset += 8
                index += 1
            elif tag in {7, 8, 16, 19, 20}:
                offset += 2
            elif tag in {9, 10, 11, 12, 18}:
                offset += 4
            elif tag == 15:
                offset += 3
            else:
                break
            index += 1
        return values
    except Exception:
        return []


def normalize_ref(
    raw_ref: str,
    source_path: str,
    view_resolvers: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    ref = raw_ref.strip()
    if not ref:
        return []
    if "${" in ref or "<%=" in ref or " + " in ref:
        return [(ref, "unresolved:dynamic")]
    if "," in ref and not ref.startswith(("http://", "https://")):
        out: list[tuple[str, str]] = []
        for piece in split_ref_values(ref):
            out.extend(normalize_ref(piece, source_path, view_resolvers))
        return dedupe_norm_actions(out)

    parsed = urllib.parse.urlsplit(ref)
    if parsed.scheme.lower() in SKIP_SCHEMES:
        return [(ref, "skipped:scheme")]
    if parsed.scheme in {"http", "https"}:
        path = normalize_candidate_path(parsed.path)
        if is_action_endpoint(path):
            return [(ref, "record-only:endpoint")]
        return [(ref, "fetch")]
    if parsed.scheme and parsed.scheme not in {"classpath"}:
        return [(ref, "skipped:scheme")]

    original = ref
    if ref.startswith("classpath*:"):
        ref = ref[len("classpath*:") :]
        if "*" in ref and not is_safe_wildcard(ref):
            return [(original, "unresolved:wildcard")]
        return [(path, "fetch") for path in expand_wildcard("/WEB-INF/classes/" + ref.lstrip("/"))]
    if ref.startswith("classpath:"):
        ref = ref[len("classpath:") :]
        return [(path, "fetch") for path in expand_wildcard("/WEB-INF/classes/" + ref.lstrip("/"))]

    if looks_like_java_class(ref):
        return [(class_name_to_path(ref), "fetch")]
    if looks_like_jvm_class(ref):
        return [(jvm_class_to_path(ref), "fetch")]

    if ref.startswith(("WEB-INF/", "META-INF/", "BOOT-INF/")):
        path = "/" + ref
    elif ref.startswith(("/WEB-INF/", "/META-INF/", "/BOOT-INF/")):
        path = ref
    elif ref.startswith("/"):
        path = ref
    elif looks_like_classpath_resource(ref, source_path):
        path = "/WEB-INF/classes/" + ref.lstrip("/")
    elif is_view_name(ref):
        return [(candidate, "fetch") for candidate in view_name_candidates(ref, view_resolvers, explicit=True)]
    else:
        base = source_path
        if not base.startswith("/"):
            base = "/" + base
        path = posixpath.normpath(posixpath.join(posixpath.dirname(base), ref))

    if "*" in path:
        if not is_safe_wildcard(path):
            return [(path, "unresolved:wildcard")]
        return [(candidate, "fetch") for candidate in expand_wildcard(path)]
    norm = normalize_candidate_path(path)
    if not norm:
        return []
    if is_action_endpoint(norm):
        return [(norm, "record-only:endpoint")]
    return [(norm, "fetch")]


def split_ref_values(value: str) -> list[str]:
    pieces = re.split(r"[,;\s]+", value.strip())
    return [piece.strip() for piece in pieces if piece.strip()]


def is_reference_candidate(value: str) -> bool:
    value = value.strip()
    if not value or len(value) > 500:
        return False
    if value.startswith(("classpath:", "classpath*:", "/WEB-INF/", "WEB-INF/", "/META-INF/", "META-INF/", "/BOOT-INF/", "BOOT-INF/")):
        return True
    if any(value.lower().endswith(ext) for ext in REFERENCE_EXTENSIONS):
        return True
    if re.search(r"[\w./-]+(?:\.do|\.mc|\.action|/api/[\w./-]*)", value, re.I):
        return True
    return False


def looks_like_java_class(value: str) -> bool:
    value = value.strip()
    return (
        re.fullmatch(r"(?:[a-z_][A-Za-z0-9_$]*\.){2,}[A-Z][A-Za-z0-9_$]*", value) is not None
        and not value.startswith(LIB_CLASS_PREFIXES)
    )


def looks_like_java_package(value: str) -> bool:
    return re.fullmatch(r"(?:[a-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*", value.strip()) is not None


def looks_like_jvm_class(value: str) -> bool:
    value = value.strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    if value.startswith(tuple(prefix.replace(".", "/") for prefix in LIB_CLASS_PREFIXES)):
        return False
    return re.fullmatch(r"(?:[a-z_][A-Za-z0-9_$]*/){2,}[A-Z][A-Za-z0-9_$]*", value) is not None


def class_name_to_path(class_name: str) -> str:
    class_name = class_name.strip()
    if not looks_like_java_class(class_name):
        return ""
    return "/WEB-INF/classes/" + class_name.replace(".", "/") + ".class"


def jvm_class_to_path(value: str) -> str:
    value = value.strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    if not looks_like_jvm_class(value):
        return ""
    return "/WEB-INF/classes/" + value + ".class"


def looks_like_classpath_resource(ref: str, source_path: str) -> bool:
    if ref.startswith(("../", "./")):
        return False
    lower = ref.lower()
    if lower.endswith((".xml", ".properties", ".yml", ".yaml", ".class", ".tld", ".sql")) and "/" in ref:
        return not source_path.lower().endswith((".jsp", ".html", ".css"))
    return False


def is_action_endpoint(path: str) -> bool:
    lower = path.lower().split("?", 1)[0]
    return lower.endswith(ACTION_EXTENSIONS) or lower.startswith("/api/") or "/api/" in lower


def is_view_name(value: str) -> bool:
    if not value or value.startswith(("redirect:", "forward:", "http://", "https://")):
        return False
    if value.endswith(REFERENCE_EXTENSIONS):
        return False
    if value.startswith("/") and not value.startswith("/WEB-INF/"):
        return False
    return re.fullmatch(r"[A-Za-z0-9_./-]{2,120}", value) is not None


def view_name_candidates(
    view: str,
    view_resolvers: list[tuple[str, str]],
    *,
    explicit: bool,
) -> list[str]:
    view = view.strip()
    if not view or view.startswith(("redirect:", "forward:", "http://", "https://")):
        return []
    if view.startswith("/WEB-INF/") and view.endswith((".jsp", ".jspx", ".vm", ".ftl")):
        return [view]
    if view.startswith("/") and not view.startswith("/WEB-INF/"):
        return []
    if view.endswith((".jsp", ".jspx", ".vm", ".ftl")):
        return [view]
    candidates: list[str] = []
    resolvers = view_resolvers or (COMMON_VIEW_PREFIXES if explicit else ())
    for resolver in resolvers:
        if isinstance(resolver, tuple):
            prefix, suffix = resolver
        else:
            prefix, suffix = resolver, ".jsp"
        candidates.append(prefix.rstrip("/") + "/" + view.lstrip("/") + suffix)
    return dedupe(candidates)


def is_safe_wildcard(path: str) -> bool:
    return path.count("*") == 1 and "applicationContext*" in path and path.endswith(".xml")


def expand_wildcard(path: str) -> list[str]:
    if "*" not in path:
        return [normalize_candidate_path(path)]
    if not is_safe_wildcard(path):
        return []
    prefix, suffix = path.split("*", 1)
    return [normalize_candidate_path(prefix + infix + suffix) for infix in APPCTX_WILDCARD_EXPANSIONS]


def parse_js_file_ref(value: str) -> bool:
    return value.lower().endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".xml", ".json", ".properties"))


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def dedupe_pairs(values: Iterable[tuple[str, int]]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for value in values:
        if value[0] and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def dedupe_norm_actions(values: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def local_name(name: str) -> str:
    if "}" in name:
        name = name.rsplit("}", 1)[1]
    if ":" in name:
        name = name.rsplit(":", 1)[1]
    return name


def load_headers(path: Path | None) -> dict[str, str]:
    headers = dict(DEFAULT_HEADERS)
    if not path:
        return headers
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise SystemExit(f"invalid header line: {line}")
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def resolve_cfr_jar(explicit: Path | None) -> Path | None:
    if explicit:
        return explicit
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "cfr-0.152.jar",
        Path.cwd() / "cfr.jar",
        Path.cwd() / "cfr-0.152.jar",
        Path.cwd() / "tools" / "cfr.jar",
        Path.cwd() / "tools" / "cfr-0.152.jar",
        script_dir / "cfr.jar",
        script_dir / "tools" / "cfr.jar",
        script_dir / "tools" / "cfr-0.152.jar",
        Path("/tmp/cfr.jar"),
        Path("/tmp/cfr-0.152.jar"),
        Path("/tmp/tools/cfr.jar"),
        Path("/tmp/tools/cfr-0.152.jar"),
        Path("/tmp/mobile2/cfr.jar"),
        Path("/tmp/mobile2/cfr-0.152.jar"),
        Path("/tmp/mobile2/tools/cfr.jar"),
        Path("/tmp/mobile2/tools/cfr-0.152.jar"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def sqlmap_class_candidates(resource: str, scanner: WebInfScanner) -> list[str]:
    resource = resource.strip()
    if resource.startswith(("classpath:", "classpath*:")):
        resource = resource.split(":", 1)[1]
    resource = resource.lstrip("/")
    if not resource.lower().endswith(".xml"):
        return []
    stem = Path(resource).stem
    class_stem = sqlmap_stem_to_class_stem(stem)
    if not class_stem:
        return []

    root_package = sqlmap_resource_root_package(resource)
    package_candidates: set[str] = set()
    for package_name in scanner.component_packages:
        if root_package and not package_name.startswith(root_package + "."):
            continue
        if package_name.endswith((".service", ".dao")):
            package_candidates.add(package_name)

    if root_package:
        package_candidates.update(
            {
                root_package + ".service",
                root_package + ".dao",
                root_package + ".controller",
            }
        )

    class_names: set[str] = set()
    for package_name in package_candidates:
        if package_name.endswith(".service"):
            class_names.add(package_name + "." + class_stem + "Service")
        elif package_name.endswith(".dao"):
            class_names.add(package_name + "." + class_stem + "DAO")
        elif package_name.endswith(".controller"):
            class_names.add(package_name + "." + class_stem + "Controller")
    if root_package:
        class_names.add(root_package + ".dto." + class_stem + "DTO")
        if "email" in resource.lower():
            class_names.add(root_package + ".dto." + class_stem + "TemplateDTO")

    return [class_name_to_path(name) for name in sorted(class_names) if class_name_to_path(name)]


def sqlmap_resource_root_package(resource: str) -> str:
    parts = [part for part in resource.split("/") if part]
    if "sqlmap" in parts:
        idx = parts.index("sqlmap")
        if idx >= 1:
            return ".".join(parts[:idx])
    if len(parts) >= 3:
        return ".".join(parts[:-3])
    return ""


def sqlmap_stem_to_class_stem(stem: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_$]", "", stem)
    if not stem:
        return ""
    known = {
        "skb": "Skb",
        "admin": "Admin",
        "advert": "Advert",
        "board": "Board",
        "common": "Common",
        "email": "Email",
        "member": "Member",
        "product": "Product",
        "bogji": "Bogji",
        "mall": "Mall",
        "usr": "Usr",
        "mail": "Mail",
        "community": "Community",
        "reserve": "Reserve",
        "hns": "Hns",
        "gt": "GT",
        "mb": "Mb",
    }
    lowered = stem.lower()
    pieces: list[str] = []
    cursor = 0
    tokens = sorted(known, key=len, reverse=True)
    while cursor < len(lowered):
        matched = ""
        for token in tokens:
            if lowered.startswith(token, cursor):
                matched = token
                break
        if matched:
            pieces.append(known[matched])
            cursor += len(matched)
        else:
            pieces.append(stem[cursor].upper())
            cursor += 1
    if pieces and "".join(piece.lower() for piece in pieces) == lowered:
        if all(len(piece) == 1 for piece in pieces):
            return stem[:1].upper() + stem[1:]
        return "".join(pieces)
    if "_" in stem:
        return "".join(part[:1].upper() + part[1:] for part in stem.split("_") if part)
    return stem[:1].upper() + stem[1:]


def tsv(value: object) -> str:
    return str(value).replace("\t", " ").replace("\n", "\\n").replace("\r", "\\r")


def render_summary(payload: dict) -> str:
    counts = payload["counts"]
    items = payload["items"]
    by_type: dict[str, int] = {}
    referrers: dict[str, int] = {}
    for item in items:
        if not item.get("downloaded"):
            continue
        ext = Path(item.get("path") or "").suffix.lower() or "[no-ext]"
        by_type[ext] = by_type.get(ext, 0) + 1
        ref = item.get("referrer") or "[seed]"
        referrers[ref] = referrers.get(ref, 0) + 1
    lines = [
        "# WEB-INF Scanner Summary",
        "",
        f"- Target: `{payload['target_url']}`",
        f"- Context prefix: `{payload.get('context_prefix') or '/'}`",
        f"- Started: `{payload['started_at']}`",
        f"- Ended: `{payload['ended_at']}`",
        f"- Total discovered: {counts['discovered']}",
        f"- Attempted: {counts['attempted']}",
        f"- Downloaded: {counts['downloaded']}",
        f"- Failed: {counts['failed']}",
        f"- Error-like: {counts['error_like']}",
        f"- Skipped external: {counts['skipped_external']}",
        "",
        "## Files By Type",
        "",
    ]
    if by_type:
        lines.extend(f"- `{ext}`: {count}" for ext, count in sorted(by_type.items()))
    else:
        lines.append("- None")
    lines.extend(["", "## Top Referrers", ""])
    if referrers:
        for ref, count in sorted(referrers.items(), key=lambda item: item[1], reverse=True)[:15]:
            lines.append(f"- `{ref}`: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Unresolved Dynamic References", ""])
    unresolved = payload.get("unresolved_dynamic_references", [])
    if unresolved:
        for entry in unresolved[:50]:
            lines.append(f"- `{entry['file']}`: `{entry['raw_ref']}`")
    else:
        lines.append("- None")
    lines.extend(["", "## Sensitive Key Names", ""])
    sensitive = payload.get("sensitive_keys", [])
    if sensitive:
        for entry in sensitive:
            lines.append(f"- `{entry['file']}`: `{entry['key']}`")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GET-only WEB-INF/META-INF/BOOT-INF recursive scanner")
    parser.add_argument("--version", action="version", version=f"web-inf dumper {VERSION}")
    parser.add_argument("target_url", help="Base URL or exposed file URL")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Output directory")
    parser.add_argument("--wordlist", type=Path, default=Path.cwd() / "web-inf.txt")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--headers-file", type=Path)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-workers", type=int, default=3)
    parser.add_argument("--max-depth", type=int, default=20)
    parser.add_argument("--max-requests", type=int, default=0, help="0 means unlimited")
    parser.add_argument("--no-bruteforce", action="store_true", help="Skip initial wordlist discovery")
    parser.add_argument("--no-decompile", action="store_true", help="Skip CFR decompilation")
    parser.add_argument("--cfr-jar", type=Path)
    parser.add_argument("--allow-cross-host", action="store_true")
    parser.add_argument("--keep-error-like", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(BANNER, file=sys.stderr)
    headers = load_headers(args.headers_file)
    scanner = WebInfScanner(
        args.target_url,
        args.output,
        wordlist=args.wordlist,
        proxy=args.proxy,
        headers=headers,
        timeout=args.timeout,
        max_workers=args.max_workers,
        max_depth=args.max_depth,
        max_requests=args.max_requests,
        no_bruteforce=args.no_bruteforce,
        no_decompile=args.no_decompile,
        cfr_jar=args.cfr_jar,
        allow_cross_host=args.allow_cross_host,
        keep_error_like=args.keep_error_like,
        debug=args.debug,
    )
    try:
        return scanner.run()
    except KeyboardInterrupt:
        if scanner.progress_line_active:
            print(file=sys.stderr)
        print("Bye bye", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
