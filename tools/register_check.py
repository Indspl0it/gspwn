"""Check documentation prose against the project's writing register.

The register bans a family of constructions that a read-through does not
reliably catch, because they scan as labels: question-shaped section headings
("What the build phase pins") and question-shaped table column headers ("What
it controls"). One reference table carried the latter ten times before this
check existed.

Run it over the whole documentation tree:

    python3 tools/register_check.py

Or over specific files:

    python3 tools/register_check.py docs/src/content/docs/index.mdx

Exits 1 when any non-exempt hit is found, so CI fails on a regression.

Exempt content is listed in EXEMPT below, each entry with the reason it is
exempt. Verbatim reproductions are immutable: documentation has to match what
the program actually prints, so a banned construction inside quoted tool
output is a defect in the tool, not in the page.
"""
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_ROOTS = [
    os.path.join("docs", "src", "content", "docs"),
    os.path.join("docs", "src", "components"),
]
SUFFIXES = (".md", ".mdx", ".astro")

# path suffix -> (rule name or "*" for all, reason)
EXEMPT = {
    "project/faq.md": (
        "*",
        "A genuine question-and-answer page. The register rule exempts one "
        "explicitly: questions are its structure.",
    ),
    "project/changelog.md": (
        "rather",
        "Entries quote commit subjects verbatim.",
    ),
    "components/ThemeProvider.astro": (
        "rather",
        "A source comment. The register governs prose for a reader, not code "
        "comments.",
    ),
    "knowledgebase/gsp-offload.mdx": (
        "marketing adjective",
        "Robust channel is NVIDIA's name for the recovery mechanism. Renaming "
        "it would stop the page matching the platform's own terminology.",
    ),
    "knowledgebase/scheduling.mdx": (
        "marketing adjective",
        "Robust channel, as above.",
    ),
}

PATTERNS = [
    ("em dash", r"—|&mdash;"),
    ("en dash", r"–|&ndash;"),
    ("curly quote", r"[‘’“”]"),
    ("rather", r"\brather\b"),
    ("instead of", r"\binstead of\b"),
    ("as opposed to", r"\bas opposed to\b"),
    ("not just / not only", r"\bnot (just|only)\b"),
    # "The generation, not the segment, sets the floor" is the same
    # contrastive family as "rather than" and reads the same way.
    ("appositive contrast", r",\s+not\s+(a|an|the|its|his|her|their)\b"),
    ("second person", r"\byou\b|\byour\b|\bwe\b|\bour\b|\blet's\b"),
    ("filler opener", r"\bIn order to\b|\bAdditionally\b|\bFurthermore\b|"
                      r"\bIt is (important|worth) (to note|noting)\b"),
    ("copula avoidance", r"\bserves as\b|\bstands as\b|\bacts as\b|"
                        r"\brepresents a\b|\bfunctions as\b|\bboasts\b"),
    ("marketing adjective", r"\bcrucial\b|\bpivotal\b|\brobust\b|\bseamless\b|"
                            r"\bcomprehensive\b|\bpowerful\b|\belegant\b|"
                            r"\bvibrant\b|\bgroundbreaking\b|\bleverage\b|"
                            r"\bdelve\b|\bshowcase\b|\bunderscore\b|"
                            r"\btestament\b"),
    ("emoji", "[\U0001F300-\U0001FAFF☀-➿]"),
    # Text about the text. A page states its subject; it does not announce
    # what it is about to state, or point back at what it already stated.
    ("meta-commentary", r"\bit is worth (noting|stating|saying|mentioning)\b|"
                       r"\bworth stating plainly\b|"
                       r"\bas (noted|discussed|mentioned|stated) (above|earlier|below)\b|"
                       r"\bin other words\b|\bthat said\b|"
                       r"\bat the end of the day\b|"
                       r"\bthis (page|section) (will|covers|explains)\b"),
    # Cleft constructions. "Its envelope is what puts the parts on a module"
    # is "its envelope puts the parts on a module" with emphasis bolted on.
    # The plain form states the same fact in fewer words.
    # "is where" is deliberately absent: it has a literal locative use, as in
    # "local is where the compiler spills registers".
    ("cleft construction", r"\b(is|are|was|were) what\b|\bis the one (that|the|most|least)\b|"
                          r"\b(is|are) how\b|\bwhat it (shares|does|owns) is\b"),
    # Withholding a fact to set it up, or narrating a reaction to it. Both
    # read as a magazine feature. The fact goes in the sentence that
    # introduces it.
    ("narrative framing", r"\bthe (usual|real|actual) (surprise|catch|trick|question|answer|reason)\b|"
                         r"\bturns out\b|\bis the one that\b|"
                         r"\bmeans something other than\b|\bthe (trick|catch) is\b|"
                         r"\bis where the .{0,30}happens\b"),
]

QUESTION_START = re.compile(r"^(what|why|how|where|when|who|which)\b", re.I)
HTML_HEADING = re.compile(r"<h[1-4][^>]*>(.*?)</h[1-4]>", re.S | re.I)
MD_HEADING = re.compile(r"^\s{0,3}#{1,4}\s+(.+?)\s*$", re.M)
TAG = re.compile(r"<[^>]+>")


def exemption(rel_path, rule):
    """The reason rule is exempt on rel_path, or None."""
    norm = rel_path.replace(os.sep, "/")
    for suffix, (exempt_rule, reason) in EXEMPT.items():
        if norm.endswith(suffix) and exempt_rule in ("*", rule):
            return reason
    return None


def label_is_question(text):
    """Is this heading or column header a question wearing a label's clothes?

    A one-word cell is a label: "When" and "Why" name a column. Two or more
    words starting with a question word is the banned form.
    """
    if not text:
        return False
    if text.endswith("?"):
        return True
    return bool(QUESTION_START.match(text)) and len(text.split()) > 1


def _blank(match):
    """Replace a region with spaces, preserving line numbers."""
    return re.sub(r"[^\n]", " ", match.group(0))


def strip_exempt_regions(src):
    """Blank code, keeping line numbers.

    Covers <style>, <script>, fenced blocks and inline code spans. Everything
    in a code span is a reproduction: a path, a command, a string literal the
    program prints, or an example of a construction being described. The
    register governs prose, and prose is what is left.

    The regions are blanked, never deleted. Deleting shifts every line number
    after the first edit, which makes the reported location useless.
    """
    out = re.sub(r"<(style|script)\b.*?</\1>", _blank, src, flags=re.S | re.I)
    out = re.sub(r"^```.*?^```", _blank, out, flags=re.S | re.M)
    out = re.sub(r"``[^`]+``", _blank, out)
    return re.sub(r"`[^`\n]+`", _blank, out)


def md_table_headers(src):
    """Yield (line_number, cell) for every markdown table header cell.

    A header row is the line directly above a row of dashes.
    """
    lines = src.split("\n")
    for i, line in enumerate(lines[:-1]):
        if "|" not in line:
            continue
        if not re.match(r"^\s*\|?[\s:|-]*-[\s:|-]*\|", lines[i + 1]):
            continue
        for cell in line.strip().strip("|").split("|"):
            yield i + 1, cell.strip()


def check_file(path, rel_path):
    """Return a list of (rule, line, detail) for one file."""
    with open(path, encoding="utf-8") as handle:
        prose = strip_exempt_regions(handle.read())

    hits = []

    def line_of(offset):
        return prose[:offset].count("\n") + 1

    for rule, pattern in PATTERNS:
        if exemption(rel_path, rule):
            continue
        flags = 0 if rule == "second person" else re.I
        for match in re.finditer(pattern, prose, flags):
            context = prose[max(0, match.start() - 40): match.end() + 40]
            hits.append((rule, line_of(match.start()),
                         " ".join(context.split())))

    if not exemption(rel_path, "question heading"):
        for match in HTML_HEADING.finditer(prose):
            text = TAG.sub("", match.group(1)).strip()
            if label_is_question(text):
                hits.append(("question heading", line_of(match.start()), text))
        for match in MD_HEADING.finditer(prose):
            text = match.group(1).strip()
            if label_is_question(text):
                hits.append(("question heading", line_of(match.start()), text))

    if not exemption(rel_path, "question column"):
        for line, cell in md_table_headers(prose):
            if label_is_question(cell):
                hits.append(("question column", line, cell))

    return sorted(set(hits), key=lambda h: (h[1], h[0]))


def collect(paths):
    """Expand the arguments into (absolute, repo-relative) file pairs."""
    if paths:
        return [(os.path.abspath(p), os.path.relpath(os.path.abspath(p),
                                                     REPO_ROOT))
                for p in paths]
    found = []
    for root in DOC_ROOTS:
        base = os.path.join(REPO_ROOT, root)
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in sorted(filenames):
                if name.endswith(SUFFIXES):
                    full = os.path.join(dirpath, name)
                    found.append((full, os.path.relpath(full, REPO_ROOT)))
    return sorted(found, key=lambda pair: pair[1])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__)
        return 0

    files = collect(args)
    if not files:
        print("register_check: no documentation files found", file=sys.stderr)
        return 1

    total = 0
    for path, rel in files:
        hits = check_file(path, rel)
        if not hits:
            continue
        total += len(hits)
        print("%s:" % rel)
        for rule, line, detail in hits:
            print("  line %-5d %-20s %s" % (line, rule, detail))

    print("register_check: %d file(s), %d hit(s)" % (len(files), total))
    if total:
        print("See ~/.claude/rules/technical-writing-register.md. If a hit is "
              "a verbatim reproduction, add it to EXEMPT with its reason.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
