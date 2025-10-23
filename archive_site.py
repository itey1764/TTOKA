#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Archive a site for static hosting (GitHub Pages friendly), with ALL images stored locally.

Features
- Sitemap discovery via robots.txt (supports sitemap index and .gz)
- If no sitemap URLs are found, seeds from --base homepage (important)
- BFS crawl of internal <a href> links up to --max-crawl hops
- Rewrites internal page links to relative paths (works under any base path)
- Downloads & rewrites:
    * <img src>, srcset (incl. <source srcset>)
    * lazyload attrs (data-src, data-original, data-lazy, data-image, data-srcset)
    * video poster, object data, iframe/embed src
    * inline CSS (style attrs) and <style> blocks
    * EXTERNAL CSS files (pulls images/fonts via url(...), rewrites)
    * meta image URLs (og:image, twitter:image)
    * inline & EXTERNAL JS: replaces literal image URLs (best-effort)
- Emits: site/ (static copy), manifest/pages.csv, site/archive-index.html
- Ensures site/index.html exists

Usage examples
  python archive_site.py --base https://ttoka.org --out site --respect-robots --mirror-externals-all --crawl-fallback --max-crawl 1

Notes
- Respect robots.txt unless you control the site (use --ignore-robots only with permission).
- Dynamic client-side states aren’t rendered; this archives fetched HTML + static assets.
"""

import argparse, csv, gzip, io, os, re, sys, time, urllib.parse
from collections import deque, defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import List, Set, Tuple, Dict, Optional

import requests
from bs4 import BeautifulSoup

# ----------------- Config -----------------

DEFAULT_HEADERS = {
    "User-Agent": "SiteArchiver/1.2 (+https://github.com/)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close",
}

IMAGE_EXTS = {".png",".jpg",".jpeg",".webp",".gif",".svg",".avif",".ico"}
ASSET_DOWNLOAD_EXTS = IMAGE_EXTS | {".css",".js",".mjs",".woff",".woff2",".ttf",".otf",".eot",".pdf",".mp4",".webm",".mp3",".ogg",".wav"}
HTML_EXTS = {".html",".htm",""}

CSS_URL_RE = re.compile(r"url\(([^)]+)\)", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r"@import\s*(?:url\()?['\"]?([^)\"';]+)", re.IGNORECASE)
ABS_URL_RE = re.compile(r"https?://[^\s'\"()<>]+", re.IGNORECASE)

@dataclass
class Options:
    base: str
    out_dir: Path
    manifest_dir: Path
    respect_robots: bool
    mirror_externals_images: bool
    mirror_externals_all: bool
    crawl_fallback: bool
    max_crawl_depth: int
    delay: float
    timeout: float

# ----------------- URL & path helpers -----------------

def norm_url(u: str) -> str:
    if not u: return u
    u, _ = urllib.parse.urldefrag(u.strip())
    p = urllib.parse.urlsplit(u)
    scheme = (p.scheme or "https").lower()
    netloc = p.netloc.lower()
    path = p.path or "/"
    q = ("?"+p.query) if p.query else ""
    return urllib.parse.urlunsplit((scheme, netloc, path, q, ""))

def join_url(base_url: str, href: str) -> Optional[str]:
    href = (href or "").strip().strip("'\"")
    if not href or href.startswith(("data:","mailto:","tel:","#")):
        return None
    if href.startswith("//"):
        sch = urllib.parse.urlsplit(base_url).scheme or "https"
        return f"{sch}:{href}"
    return norm_url(urllib.parse.urljoin(base_url, href))

def is_same_site(u: str, base_host: str) -> bool:
    try:
        netloc = urllib.parse.urlsplit(u).netloc.lower()
        return (netloc == "" or netloc.endswith(base_host))
    except Exception:
        return False

def is_likely_html(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path
    ext = Path(path).suffix.lower()
    return ext in HTML_EXTS

def path_for_page(url: str) -> str:
    """
    Map a page URL to output path:
      /            -> index.html
      /about       -> about/index.html
      /about/      -> about/index.html
      /post/42     -> post/42/index.html
      /file.html   -> file.html
      with ?q=...  -> adds __q_<hash> before index.html or before .html
    """
    p = urllib.parse.urlsplit(url)
    path = p.path or "/"
    q = "__q_" + str(abs(hash(p.query)) % (10**10)) if p.query else ""
    if path.endswith("/"):
        return path.lstrip("/") + q + "index.html"
    ext = Path(path).suffix.lower()
    if ext in {".html",".htm"}:
        name = path.lstrip("/")
        if q: name = name[:-len(ext)] + q + ext
        return name
    return path.lstrip("/") + "/" + q + "index.html"

def path_for_asset(url: str, out_assets_root: Path) -> str:
    p = urllib.parse.urlsplit(url)
    host = p.netloc or "local"
    clean = p.path.lstrip("/")
    if not clean or clean.endswith("/"):
        clean += "index"
    return str(out_assets_root.joinpath(host, clean))

def ensure_dir(p: Path): p.parent.mkdir(parents=True, exist_ok=True)

def rel_href(from_path: Path, to_path: Path) -> str:
    rel = os.path.relpath(to_path.as_posix(), start=from_path.parent.as_posix())
    return rel.replace("\\","/")

def http_get(session: requests.Session, url: str, timeout: float) -> requests.Response:
    r = session.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r

# ----------------- Sitemap discovery -----------------

def discover_sitemaps(session: requests.Session, base: str, ignore_robots: bool) -> List[str]:
    sitemaps = []
    p = urllib.parse.urlsplit(base)
    robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
    if not ignore_robots:
        try:
            r = http_get(session, robots_url, timeout=15)
            for line in r.text.splitlines():
                if line.strip().lower().startswith("sitemap:"):
                    sm = norm_url(line.split(":",1)[1].strip())
                    if sm and sm not in sitemaps: sitemaps.append(sm)
        except Exception:
            pass
    for cand in ("/sitemap.xml","/sitemap_index.xml","/sitemap.xml.gz"):
        u = norm_url(urllib.parse.urljoin(base, cand))
        if u not in sitemaps: sitemaps.append(u)
    return sitemaps

def parse_sitemap_xml(content: bytes) -> Tuple[List[str], List[str]]:
    text = content.decode("utf-8", errors="replace")
    sitemaps, urls = [], []
    if "<sitemapindex" in text:
        for m in re.findall(r"<loc>(.*?)</loc>", text, flags=re.I|re.S):
            sitemaps.append(norm_url(m.strip()))
    else:
        for m in re.findall(r"<loc>(.*?)</loc>", text, flags=re.I|re.S):
            urls.append(norm_url(m.strip()))
    return sitemaps, urls

def fetch_all_sitemap_urls(session: requests.Session, base: str, respect_robots: bool) -> List[str]:
    seen, pages = set(), set()
    q = deque(discover_sitemaps(session, base, ignore_robots=not respect_robots))
    while q:
        sm = q.popleft()
        if sm in seen: continue
        seen.add(sm)
        try:
            r = http_get(session, sm, timeout=30)
            data = r.content
            if sm.endswith(".gz") or r.headers.get("Content-Type","").endswith("gzip"):
                try: data = gzip.decompress(data)
                except Exception: pass
            subs, urls = parse_sitemap_xml(data)
            for s in subs:
                if s not in seen: q.append(s)
            for u in urls: pages.add(u)
        except Exception:
            continue
    return sorted(pages)

# ----------------- CSS/JS rewriting -----------------

def download_asset(session, url, out_path: Path, timeout: float, delay: float) -> bool:
    try:
        ensure_dir(out_path)
        r = http_get(session, url, timeout=timeout)
        with open(out_path, "wb") as f: f.write(r.content)
        time.sleep(delay)
        return True
    except Exception:
        return False

def rewrite_css_text(session, css_text: str, css_base_url: str, from_file_path: Path,
                     out_assets_root: Path, options: Options) -> str:
    # url(...)
    def repl_url(m):
        raw = m.group(1).strip().strip('\'"')
        full = join_url(css_base_url, raw)
        if not full: return m.group(0)
        ext = Path(urllib.parse.urlsplit(full).path).suffix.lower()
        same_site = is_same_site(full, urllib.parse.urlsplit(options.base).netloc)
        is_img = ext in IMAGE_EXTS
        mirror_ok = same_site or options.mirror_externals_all or (options.mirror_externals_images and is_img)
        if mirror_ok:
            asset_abs = Path(path_for_asset(full, out_assets_root))
            if download_asset(session, full, asset_abs, options.timeout, options.delay):
                return f"url({rel_href(from_file_path, asset_abs)})"
        return f"url({full})"

    css_text = CSS_URL_RE.sub(repl_url, css_text)

    # @import ...
    def repl_import(m):
        raw = m.group(1).strip().strip('\'"')
        full = join_url(css_base_url, raw)
        if not full: return m.group(0)
        css_local_abs = Path(path_for_asset(full, out_assets_root))
        if download_asset(session, full, css_local_abs, options.timeout, options.delay):
            try:
                text = css_local_abs.read_text(encoding="utf-8", errors="replace")
            except Exception:
                text = ""
            new_text = rewrite_css_text(session, text, full, css_local_abs, out_assets_root, options)
            if new_text != text:
                css_local_abs.write_text(new_text, encoding="utf-8")
            return f"@import url({rel_href(from_file_path, css_local_abs)})"
        return m.group(0)

    css_text = CSS_IMPORT_RE.sub(repl_import, css_text)
    return css_text

def postprocess_css_file(session, css_url: str, css_local_abs: Path, out_assets_root: Path, options: Options):
    try:
        text = css_local_abs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    new_text = rewrite_css_text(session, text, css_url, css_local_abs, out_assets_root, options)
    if new_text != text:
        css_local_abs.write_text(new_text, encoding="utf-8")

def rewrite_js_text_for_images(session, js_text: str, js_base_url: str, from_file_path: Path,
                               out_assets_root: Path, options: Options) -> str:
    # Replace literal image URLs in JS (best-effort).
    seen = set()
    for match in ABS_URL_RE.findall(js_text):
        if match in seen: continue
        seen.add(match)
        full = norm_url(match)
        ext = Path(urllib.parse.urlsplit(full).path).suffix.lower()
        if ext not in IMAGE_EXTS: continue
        same_site = is_same_site(full, urllib.parse.urlsplit(options.base).netloc)
        mirror_ok = same_site or options.mirror_externals_all or options.mirror_externals_images
        if not mirror_ok: continue
        asset_abs = Path(path_for_asset(full, out_assets_root))
        if download_asset(session, full, asset_abs, options.timeout, options.delay):
            js_text = js_text.replace(match, rel_href(from_file_path, asset_abs))
    return js_text

def postprocess_js_file(session, js_url: str, js_local_abs: Path, out_assets_root: Path, options: Options):
    try:
        text = js_local_abs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    new_text = rewrite_js_text_for_images(session, text, js_url, js_local_abs, out_assets_root, options)
    if new_text != text:
        js_local_abs.write_text(new_text, encoding="utf-8")

# ----------------- Page processing -----------------

def parse_srcset_list(value: str) -> List[str]:
    urls = []
    for part in (value or "").split(","):
        token = part.strip().split()
        if token:
            urls.append(token[0])
    return urls

def process_html_page(session: requests.Session, page_url: str, out_root: Path,
                      out_assets_root: Path, options: Options) -> Tuple[Path, Dict[str, List[str]], List[str]]:
    r = http_get(session, page_url, timeout=options.timeout)
    soup = BeautifulSoup(r.content, "lxml")
    base_for_page = page_url

    assets: Dict[str, List[str]] = defaultdict(list)
    internal_links: List[str] = []

    # <base href="...">
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_for_page = join_url(page_url, base_tag["href"]) or page_url

    page_dst_rel = path_for_page(page_url)
    page_dst_abs = out_root.joinpath(page_dst_rel)

    def is_img_url(u: str) -> bool:
        ext = Path(urllib.parse.urlsplit(u).path).suffix.lower()
        return ext in IMAGE_EXTS

    def should_mirror_asset(u: str, is_image_guess: bool) -> bool:
        same_site = is_same_site(u, urllib.parse.urlsplit(options.base).netloc)
        if same_site: return True
        if options.mirror_externals_all: return True
        if options.mirror_externals_images and is_image_guess: return True
        return False

    def mirror_and_rewrite(url: str, from_file: Path) -> Optional[str]:
        asset_abs = Path(path_for_asset(url, out_assets_root))
        ok = download_asset(session, url, asset_abs, options.timeout, options.delay)
        if not ok: return None
        return rel_href(from_file, asset_abs)

    def handle_attr(el, attr, kind, treat_as_image=False):
        raw = el.get(attr)
        if not raw: return
        full = join_url(page_url, raw)
        if not full: return
        # Internal HTML link → rewrite to our saved page path + enqueue
        if kind == "href":
            if is_likely_html(full) and is_same_site(full, urllib.parse.urlsplit(options.base).netloc):
                internal_links.append(norm_url(full))
                el[attr] = rel_href(Path(page_dst_rel), out_root.joinpath(path_for_page(full)))
                return
        # Assets & external links
        is_image = treat_as_image or is_img_url(full)
        if should_mirror_asset(full, is_image):
            local_rel = mirror_and_rewrite(full, Path(page_dst_rel))
            if local_rel:
                el[attr] = local_rel
                assets[kind].append(full)
                return
        el[attr] = full
        assets[kind].append(full)

    # link (css/icons/others)
    for link in soup.find_all("link"):
        rels = " ".join(link.get("rel", [])).lower()
        if link.get("href"):
            if "stylesheet" in rels:
                handle_attr(link, "href", "css", treat_as_image=False)
                href = link.get("href")
                # If now local, postprocess CSS (pull url(...) assets)
                if href and not href.startswith(("http://","https://")):
                    css_local_abs = (Path(page_dst_rel).parent / href).resolve()
                    parts = css_local_abs.as_posix().split("/assets/",1)
                    css_url = page_url if len(parts)==1 else f"https://{parts[1].split('/',1)[0]}/" + "/".join(parts[1].split('/')[1:])
                    postprocess_css_file(session, css_url, css_local_abs, out_assets_root, options)
            elif any(x in rels for x in ("icon","shortcut icon","apple-touch-icon")):
                handle_attr(link, "href", "icon", treat_as_image=True)
            else:
                handle_attr(link, "href", "generic", treat_as_image=False)

    # scripts
    for sc in soup.find_all("script"):
        if sc.get("src"):
            handle_attr(sc, "src", "js", treat_as_image=False)
            src = sc.get("src")
            if src and not src.startswith(("http://","https://")):
                js_local_abs = (Path(page_dst_rel).parent / src).resolve()
                parts = js_local_abs.as_posix().split("/assets/",1)
                js_url = page_url if len(parts)==1 else f"https://{parts[1].split('/',1)[0]}/" + "/".join(parts[1].split('/')[1:])
                postprocess_js_file(session, js_url, js_local_abs, out_assets_root, options)
        else:
            txt = sc.string or sc.text or ""
            if txt:
                new_txt = rewrite_js_text_for_images(session, txt, page_url, Path(page_dst_rel), out_assets_root, options)
                if new_txt != txt:
                    if sc.string is not None: sc.string.replace_with(new_txt)
                    else: sc.clear(); sc.append(new_txt)

    # images & lazyload
    for img in soup.find_all("img"):
        if img.get("src"):
            handle_attr(img, "src", "img", treat_as_image=True)
        for att in ("srcset","data-srcset"):
            if img.get(att):
                parts = img.get(att)
                new_parts = []
                for token in parts.split(","):
                    seg = token.strip()
                    if not seg: continue
                    u = seg.split()[0]; rest = seg[len(u):]
                    full = join_url(page_url, u)
                    if not full: continue
                    if should_mirror_asset(full, True):
                        asset_abs = Path(path_for_asset(full, out_assets_root))
                        if download_asset(session, full, asset_abs, options.timeout, options.delay):
                            new_parts.append(rel_href(Path(page_dst_rel), asset_abs) + rest)
                            assets["img"].append(full)
                            continue
                    new_parts.append(full + rest)
                img[att] = ", ".join(new_parts)
        for att in ("data-src","data-original","data-lazy","data-image"):
            if img.get(att):
                before = img.get(att)
                handle_attr(img, att, "img", treat_as_image=True)
                if img.get(att) and (not img.get("src") or img.get("src","").startswith(("data:",""))):
                    img["src"] = img.get(att)

    # <picture><source>
    for source in soup.find_all("source"):
        if source.get("src"):
            handle_attr(source, "src", "img", treat_as_image=True)
        if source.get("srcset"):
            parts = source.get("srcset")
            new_parts = []
            for token in parts.split(","):
                seg = token.strip()
                if not seg: continue
                u = seg.split()[0]; rest = seg[len(u):]
                full = join_url(page_url, u)
                if not full: continue
                if should_mirror_asset(full, True):
                    asset_abs = Path(path_for_asset(full, out_assets_root))
                    if download_asset(session, full, asset_abs, options.timeout, options.delay):
                        new_parts.append(rel_href(Path(page_dst_rel), asset_abs) + rest)
                        assets["img"].append(full)
                        continue
                new_parts.append(full + rest)
            source["srcset"] = ", ".join(new_parts)

    # media
    for tag in soup.find_all(["video","audio","track","object","iframe","embed"]):
        for att in ("poster","data","src"):
            if tag.get(att):
                treat_img = (att=="poster")
                handle_attr(tag, att, "media", treat_as_image=treat_img)

    # inline styles + <style>
    for el in soup.find_all(style=True):
        css = el["style"]
        new_css = rewrite_css_text(session, css, base_for_page, Path(page_dst_rel), out_assets_root, options)
        el["style"] = new_css
    for st in soup.find_all("style"):
        css = st.string or st.text or ""
        new_css = rewrite_css_text(session, css, base_for_page, Path(page_dst_rel), out_assets_root, options)
        if st.string is not None: st.string.replace_with(new_css)
        else: st.clear(); st.append(new_css)

    # anchors (internal pages)
    for a in soup.find_all("a", href=True):
        handle_attr(a, "href", "href", treat_as_image=False)

    # Save HTML
    ensure_dir(page_dst_abs)
    with open(page_dst_abs, "wb") as f:
        f.write(soup.encode(formatter="html"))

    return page_dst_abs, assets, internal_links

# ----------------- Output helpers -----------------

def write_index(out_root: Path, page_map: Dict[str, Path]):
    lines = [
        "<!doctype html><meta charset='utf-8'>",
        "<title>Offline Archive Index</title>",
        "<h1>Offline Archive Index</h1>",
        "<p>Pages mirrored from the sitemap and crawl. All images were made local.</p>",
        "<ul>",
    ]
    for url, path in sorted(page_map.items()):
        rel = os.path.relpath(path.as_posix(), start=out_root.as_posix()).replace("\\","/")
        lines.append(f"<li><a href='{escape(rel)}'>{escape(url)}</a></li>")
    lines.append("</ul>")
    out_root.joinpath("archive-index.html").write_text("\n".join(lines), encoding="utf-8")

def ensure_root_index(out_root: Path):
    idx = out_root.joinpath("index.html")
    if idx.exists(): return
    ai = out_root.joinpath("archive-index.html")
    if ai.exists():
        idx.write_text(ai.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    else:
        idx.write_text("<!doctype html><meta charset=utf-8><p>No index yet.</p>", encoding="utf-8")

# ----------------- Main orchestration -----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Base URL, e.g., https://ttoka.org")
    ap.add_argument("--out", default="site", help="Output folder for static copy")
    ap.add_argument("--respect-robots", action="store_true", help="Respect robots.txt (default behavior)")
    ap.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt (ONLY if you have permission)")
    ap.add_argument("--mirror-externals-images", action="store_true", help="Download external images")
    ap.add_argument("--mirror-externals-all", action="store_true", help="Download ALL external assets (css/js/fonts/images)")
    ap.add_argument("--crawl-fallback", action="store_true", help="Crawl internal anchors in addition to sitemap")
    ap.add_argument("--max-crawl", type=int, default=1, help="Crawl depth (hops) beyond seeds (0..3 recommended)")
    ap.add_argument("--delay", type=float, default=0.25, help="Delay between requests (seconds)")
    ap.add_argument("--timeout", type=float, default=30, help="HTTP timeout (seconds)")
    args = ap.parse_args()

    if args.ignore_robots and args.respect_robots:
        print("Choose either --respect-robots OR --ignore-robots, not both.", file=sys.stderr); sys.exit(2)

    options = Options(
        base=norm_url(args.base),
        out_dir=Path(args.out).resolve(),
        manifest_dir=Path("manifest").resolve(),
        respect_robots=(args.respect_robots or not args.ignore_robots),
        mirror_externals_images=bool(args.mirror_externals_images or args.mirror_externals_all),
        mirror_externals_all=bool(args.mirror_externals_all),
        crawl_fallback=bool(args.crawl_fallback),
        max_crawl_depth=max(0, int(args.max_crawl)),
        delay=float(args.delay),
        timeout=float(args.timeout),
    )

    options.out_dir.mkdir(parents=True, exist_ok=True)
    options.manifest_dir.mkdir(parents=True, exist_ok=True)
    assets_root = options.out_dir.joinpath("assets"); assets_root.mkdir(parents=True, exist_ok=True)

    base_host = urllib.parse.urlsplit(options.base).netloc.lower()
    session = requests.Session()

    # 1) Seeds: sitemap URLs (same-site only). If none, seed with homepage.
    print("Discovering sitemap URLs…", file=sys.stderr)
    sitemap_urls = fetch_all_sitemap_urls(session, options.base, options.respect_robots)
    sitemap_urls = [u for u in sitemap_urls if is_same_site(u, base_host)]
    if not sitemap_urls:
        print("No URLs from sitemap; seeding with base URL.", file=sys.stderr)
        sitemap_urls = [options.base]

    # 2) Crawl (BFS) up to max depth
    saved_pages: Dict[str, Path] = {}
    seen: Set[str] = set()
    q: deque = deque((u, 0) for u in sorted(set(sitemap_urls)))

    while q:
        url, depth = q.popleft()
        if url in seen: continue
        seen.add(url)
        if not is_likely_html(url): continue

        try:
            saved_abs, assets, discovered = process_html_page(session, url, options.out_dir, assets_root, options)
            saved_pages[url] = saved_abs
            time.sleep(options.delay)
            if options.crawl_fallback and depth < options.max_crawl_depth:
                for nxt in discovered:
                    if (nxt not in seen) and is_same_site(nxt, base_host):
                        q.append((nxt, depth + 1))
        except Exception as e:
            print(f"[WARN] Failed {url}: {e}", file=sys.stderr)

    # 3) Manifests & index
    with open(options.manifest_dir.joinpath("pages.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["url","saved_path"])
        for u,p in sorted(saved_pages.items()):
            rel = os.path.relpath(p.as_posix(), start=options.out_dir.as_posix()).replace("\\","/")
            w.writerow([u, rel])

    write_index(options.out_dir, saved_pages)
    ensure_root_index(options.out_dir)

    print(f"Done. Saved {len(saved_pages)} pages to: {options.out_dir}")
    print(f"Manifest written to: {options.manifest_dir}")

if __name__ == "__main__":
    main()