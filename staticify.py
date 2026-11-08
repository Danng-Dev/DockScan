"""Dependency-free Markdown-to-static-site renderer for DockScan documentation."""
from html import escape
from pathlib import Path
import re

from .security import private_directory, private_file


CSS = """body{margin:0;background:#10151c;color:#e8edf2;font:16px/1.55 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:2rem}nav{background:#18212c;padding:1rem 2rem;border-bottom:1px solid #314052}a{color:#72c8ff}h1,h2,h3{color:#fff;line-height:1.2;margin-top:2rem}h1{font-size:2.2rem}h2{border-bottom:1px solid #314052;padding-bottom:.35rem}code{background:#202b38;padding:.12rem .3rem;border-radius:4px}pre{background:#0a0e13;border:1px solid #314052;padding:1rem;overflow:auto;border-radius:6px}pre code{background:none;padding:0}table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{border:1px solid #405068;padding:.55rem;text-align:left;vertical-align:top}th{background:#202b38}li{margin:.25rem 0}.notice{background:#172938;border-left:4px solid #72c8ff;padding:1rem;border-radius:4px}"""


def inline(text: str, links: dict[str, str]) -> str:
    value = escape(text)
    value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
    def link(match):
        label, target = match.group(1), match.group(2)
        destination = links.get(target, target)
        return f'<a href="{escape(destination, quote=True)}">{label}</a>'
    return re.sub(r"\[([^]]+)\]\(([^)]+)\)", link, value)


def render_markdown(source: str, links: dict[str, str]) -> str:
    lines, output, in_code, table = source.splitlines(), [], False, False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            output.append("</code></pre>" if in_code else "<pre><code>")
            in_code = not in_code
        elif in_code:
            output.append(escape(line) + "\n")
        elif line.startswith("|") and "|" in line[1:]:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                index += 1
                continue
            tag = "th" if not table else "td"
            output.append("<table><thead><tr>" if not table else "<tr>")
            output.append("".join(f"<{tag}>{inline(cell, links)}</{tag}>" for cell in cells))
            output.append("</tr></thead><tbody>" if not table else "</tr>")
            table = True
        else:
            if table:
                output.append("</tbody></table>")
                table = False
            heading = re.match(r"^(#{1,3})\s+(.+)$", line)
            bullet = re.match(r"^[-*]\s+(.+)$", line)
            numbered = re.match(r"^\d+\.\s+(.+)$", line)
            if heading:
                level = len(heading.group(1)); output.append(f"<h{level}>{inline(heading.group(2), links)}</h{level}>")
            elif bullet:
                output.append(f"<li>{inline(bullet.group(1), links)}</li>")
            elif numbered:
                output.append(f"<li>{inline(numbered.group(1), links)}</li>")
            elif not line.strip():
                output.append("")
            else:
                output.append(f"<p>{inline(line, links)}</p>")
        index += 1
    if table: output.append("</tbody></table>")
    if in_code: output.append("</code></pre>")
    # Consecutive list items are valid HTML in forgiving browsers; wrap them for semantic output.
    body = "\n".join(output)
    body = re.sub(r"(?<!</li>)((?:<li>.*?</li>\n?)+)", r"<ul>\1</ul>", body, flags=re.S)
    return body


def staticify(source: Path, output: Path, title: str = "DockScan system documentation") -> list[Path]:
    if not source.is_dir():
        raise ValueError("--input must be a documentation directory")
    pages = sorted(source.glob("*.md"))
    if not pages:
        raise ValueError("no Markdown files found in input directory")
    private_directory(output)
    names = {page.name: page.with_suffix(".html").name for page in pages}
    written = []
    navigation = " · ".join(f'<a href="{escape(names[page.name])}">{escape(page.stem.replace("_", " ").title())}</a>' for page in pages)
    for page in pages:
        body = render_markdown(page.read_text(errors="replace"), names)
        document = f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{escape(title)} — {escape(page.stem)}</title><style>{CSS}</style></head><body><nav>{navigation}</nav><main>{body}</main></body></html>"
        target = output / names[page.name]
        target.write_text(document)
        private_file(target)
        written.append(target)
    index = output / "index.html"
    index.write_text((output / names.get("SYSTEM_OVERVIEW.md", pages[0].name)).read_text())
    private_file(index)
    return written + [index]
