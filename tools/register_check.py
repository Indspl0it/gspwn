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

The patterns match across one line break, because prose in the documentation
tree wraps at 80 columns and a construction split by the wrap is the same
construction. The reported line number is the line it starts on.

Code is blanked before any rule runs: <style> and <script> elements, fenced
blocks, inline code spans, and the frontmatter fence of an `.astro` component,
whose body is JavaScript and whose comments are addressed to a maintainer. The
register governs prose written for a reader, and prose is what is left.

Exempt content is listed in EXEMPT below, each entry with the reason it is
exempt. Every entry is a verbatim reproduction, and a verbatim reproduction is
immutable: documentation has to match what the program actually prints, so a
banned construction inside quoted tool output is a defect in the tool and not
in the page.
"""
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The documentation site alone. `agents/*.md` and `AGENTS.md` are deliberately
# outside this list and are not a gap to be closed. A phase brief is an
# instruction addressed to the agent executing it, so it opens "You are the
# provision-phase agent" and stays in the second person throughout. The
# register's ban on addressing the reader governs documentation written about
# the system, and applying it here would rewrite 48 hits across 13 files into
# prose that no longer instructs anyone. The rest of the register does apply to
# a brief; nothing mechanical checks it, and that is the accepted position.
DOC_ROOTS = [
    os.path.join("docs", "src", "content", "docs"),
    os.path.join("docs", "src", "components"),
]
SUFFIXES = (".md", ".mdx", ".astro")

# The character an inline code span is replaced with. It cannot occur in a
# documentation file, it is not a word character, and it is not whitespace,
# which is what lets the cleft pattern tell "the one `identifier`" from "the
# one command".
CODE_SPAN = "\x01"

# The frontmatter fence of an `.astro` component: `---` alone on the first
# line, closed by the next line that is exactly `---`. The body between them is
# JavaScript. A `---` further down the file is markup or a horizontal rule and
# opens nothing, so the pattern is anchored at the start of the source.
ASTRO_FRONTMATTER = re.compile(r"\A---\n.*?^---$", re.S | re.M)

# path suffix -> (rule name, a tuple of rule names, or "*" for all, reason)
#
# Every entry names a verbatim reproduction. A source comment reaches no entry
# here: strip_exempt_regions blanks the `.astro` frontmatter that holds one,
# which covers every component at once. An exemption list that grows one file
# at a time for one recurring cause hides the cause.
EXEMPT = {
    "knowledgebase/gsp-offload.mdx": (
        "marketing adjective",
        "Robust channel is NVIDIA's name for the recovery mechanism. Renaming "
        "it would stop the page matching the platform's own terminology.",
    ),
    "knowledgebase/scheduling.mdx": (
        "marketing adjective",
        "Robust channel, as above.",
    ),
    "knowledgebase/prior-vulnerabilities.mdx": (
        "curly quote",
        "The CVE tables reproduce NVIDIA's own bulletin sentences verbatim. "
        "CVE-2024-0137's description contains a curly apostrophe in "
        "“host’s network namespace”. Straightening it would stop "
        "the row matching what NVIDIA published.",
    ),
}

# Prose in the documentation tree wraps at 80 columns, so a two-word
# construction is routinely split across a line break and a pattern carrying a
# literal space stops matching it. Four cleft constructions survived the whole
# tree that way. Every literal space in a pattern below is compiled to this
# class instead: horizontal whitespace, or horizontal whitespace spanning one
# line break and the blockquote or list indent that follows it. One break and
# no more, so a paragraph boundary still separates two sentences.
#
# Rewriting the pattern is what preserves the line number. Joining the
# paragraphs first would match the same text and report a location in the
# joined copy, and a line-based splitter over the same tree reported 655
# candidates of which none was real.
WRAP = r"(?:[ \t]+|[ \t]*\n[ \t>]*)"


def wrap_tolerant(pattern):
    """-> pattern with every literal space also matching one line wrap.

    No pattern below writes a space inside a character class, which is the
    one construction this substitution would corrupt.
    """
    return pattern.replace(" ", WRAP)


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
    # Named Claude-family tells, catalogued from 2026 community review of
    # Opus 4.8, Opus 5 and Fable 5. "load-bearing" is the flagship: a metaphor
    # asserting structural importance without arguing for it. "seam" is absent
    # from this list on purpose, because it is a real term for a module
    # boundary and the metaphorical use cannot be separated by pattern.
    ("named Claudism", r"\bload-bearing\b|\bworth stating\b|\bcarry the argument\b|"
                      r"\bfull stop\b|\bthe trap is\b|\bstated fairly\b|"
                      r"\bquietly\b|\bmatters more\b|"
                      r"\bhere's the (thing|kicker)\b|\bthe best part\b"),
    # Cleft constructions. "Its envelope is what puts the parts on a module"
    # is "its envelope puts the parts on a module" with emphasis bolted on.
    # The plain form states the same fact in fewer words.
    # "is where" is deliberately absent: it has a literal locative use, as in
    # "local is where the compiler spills registers".
    #
    # "is the one" carries both forms. "reset is the one command allowed to
    # start over" is a determiner meaning "the only", and stays. "the grouping
    # rule is the one `cumulative_reach` is computed with" is a cleft, and the
    # relative pronoun that would give it away is an identifier instead. The
    # third alternative reads that identifier: strip_exempt_regions marks a
    # blanked code span with CODE_SPAN, so "the one" directly followed by one
    # is the cleft and "the one command" is the determiner.
    ("cleft construction", r"\b(is|are|was|were) what\b|\bis the one (that|the|most|least)\b|"
                          r"\bis the one \x01|"
                          r"\b(is|are) how\b|\bwhat it (shares|does|owns) is\b"),
    # Withholding a fact to set it up, or narrating a reaction to it. Both
    # read as a magazine feature. The fact goes in the sentence that
    # introduces it.
    ("narrative framing", r"\bthe (usual|real|actual) (surprise|catch|trick|question|answer|reason)\b|"
                         r"\bturns out\b|\bis the one that\b|"
                         r"\bmeans something other than\b|\bthe (trick|catch) is\b|"
                         r"\bis where the .{0,30}happens\b"),
    # A clause hung off a comma asserting a consequence it never measures.
    # "the flag is set, ensuring the campaign completes" states no mechanism.
    # These are the fake-depth verbs. "enabling" and "providing" are absent
    # because each carries a literal technical sense often enough that the
    # pattern would report ordinary prose.
    ("trailing -ing clause",
     r",\s+(ensuring|highlighting|reflecting|underscoring|demonstrating|"
     r"showcasing|emphasi[sz]ing|illustrating|signall?ing|paving|"
     r"allowing for|making it (possible|easier|clear|simple))\b"),
    # A datasheet states a magnitude. An intensifier is the substitute for
    # one and carries no quantity.
    # "the very next start" is a determiner and stays. "very different
    # amounts" is the intensifier standing in for the difference.
    ("hollow intensifier",
     r"\bvery (?!next|first|last|same|least|most|thing)\w|"
     r"\b(extremely|incredibly|remarkably|truly|utterly|vastly|"
     r"immensely|highly)\b"),
    # Telling a reader an operation is easy. Where it is, saying so adds
    # nothing. Where it is not, the reader is now wrong and blames themselves.
    ("dismissive qualifier",
     r"\b(simply|easily|obviously|trivially|straightforward|of course|"
     r"needless to say)\b"),
    # Marketing superlatives. None of them is a measurement.
    ("significance inflation",
     r"\b(game.?chang\w+|revolutionar\w+|cutting.edge|state.of.the.art|"
     r"best.in.class|world.class|unparalleled|unprecedented|"
     r"paradigm shift|next.generation)\b"),
    # A claim with no source. Cite the source or state the fact.
    ("vague attribution",
     r"\b(experts? (say|agree|believe)|studies show|research shows|"
     r"it is (widely|generally) (known|accepted|considered)|"
     r"many believe|is often regarded|some would argue)\b"),
    # A quantity the writer did not look up. The inventories carry the number.
    ("vague quantity",
     r"\ba (wide|broad|vast|large) (range|variety|array|number) of\b|"
     r"\ba number of\b|\bnumerous\b|\bmyriad\b|\bplethora\b"),
    # A closing that restates the section without adding a fact. Anchored to
    # a line opening with an explicit newline alternative, because check_file
    # compiles with re.I alone and a bare ^ would match the file start only.
    ("generic conclusion",
     r"(?:^|\n)\s*[>*+-]*\s*(In (conclusion|summary|short)|To summari[sz]e|"
     r"Overall|Ultimately|At its core|All in all|In essence)\b"),
    # Two hedges on one claim. A specification states the condition under
    # which the behaviour holds.
    ("hedge stack",
     r"\b(may|might|could|can) (potentially|possibly|perhaps|sometimes|"
     r"occasionally)\b|\b(generally|typically|usually) tends? to\b|"
     r"\bit (may|might) be (possible|worth)\b"),
    # Latin abbreviations. Write the English.
    ("latin abbreviation", r"\b(e\.g\.|i\.e\.|etc\.|viz\.|cf\.)"),
    # Winding up before the fact, or addressing the reader to introduce it.
    ("throat clearing",
     r"\bIn today's\b|\bIn the world of\b|\bIn the realm of\b|"
     r"\bWhen it comes to\b|\bAt the heart of\b|"
     r"\bIt goes without saying\b|\bKeep in mind\b|\bBear in mind\b|"
     # Anchored to a sentence opening. Unanchored, "note that" matches inside
     # "with the note that NVIDIA backfilled only to 2022", which is a noun.
     r"(?:^|[.!?:]\s|\n)(Note|Remember) that\b"),
    # Spatial verbs standing in for a relation the writer did not name. A
    # record is written to a path, a field is at an offset, a gate is a module
    # parameter. None of them sits, lands or lives anywhere.
    ("spatial verb",
     r"\b(sits?|sat|lands?|landed|lives?|resides?|nestles?)\s+"
     r"(in|on|at|under|inside|beside|within|beneath|next to)\b"),
    # A question in body prose sets up an answer the sentence could have
    # stated. A genuine question-and-answer page declares an exemption.
    ("body question",
     r"(?<![\w`])(So|But|And|Why|What|How|Ever wonder)\b"
     r"[^.?!\n]{5,120}\?"),
]

QUESTION_START = re.compile(r"^(what|why|how|where|when|who|which)\b", re.I)
HTML_HEADING = re.compile(r"<h[1-4][^>]*>(.*?)</h[1-4]>", re.S | re.I)
MD_HEADING = re.compile(r"^\s{0,3}#{1,4}\s+(.+?)\s*$", re.M)
TAG = re.compile(r"<[^>]+>")


def exemption(rel_path, rule):
    """The reason rule is exempt on rel_path, or None."""
    norm = rel_path.replace(os.sep, "/")
    for suffix, (exempt_rule, reason) in EXEMPT.items():
        rules = (exempt_rule,) if isinstance(exempt_rule, str) else exempt_rule
        if norm.endswith(suffix) and ("*" in rules or rule in rules):
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


def _mark_span(match):
    """Replace an inline code span with CODE_SPAN, preserving its width."""
    return CODE_SPAN * len(match.group(0))


def strip_exempt_regions(src, suffix=""):
    """Blank code, keeping line numbers.

    Covers <style>, <script>, fenced blocks and inline code spans. Everything
    in a code span is a reproduction: a path, a command, a string literal the
    program prints, or an example of a construction being described. The
    register governs prose, and prose is what is left.

    suffix is the file's extension, lowercased, and decides the file-type
    regions. For ".astro" the leading frontmatter fence goes first, because its
    body is JavaScript and its comments are written for a maintainer. Any other
    suffix, and the empty default, leave the source's opening lines alone.

    The regions are blanked, never deleted. Deleting shifts every line number
    after the first edit, which makes the reported location useless.

    An inline span is filled with CODE_SPAN and the multi-line regions with
    spaces. A cleft construction is routinely completed by an identifier, so
    the cleft pattern has to tell a code span from the prose around it, and a
    fill of spaces is indistinguishable from a line wrap into an indented list
    continuation. Both fills are non-word characters, so a pattern anchored on
    \\b reads either as a boundary and no other rule can see the difference.
    """
    out = ASTRO_FRONTMATTER.sub(_blank, src) if suffix == ".astro" else src
    out = re.sub(r"<(style|script)\b.*?</\1>", _blank, out, flags=re.S | re.I)
    out = re.sub(r"^```.*?^```", _blank, out, flags=re.S | re.M)
    out = re.sub(r"``[^`]+``", _mark_span, out)
    return re.sub(r"`[^`\n]+`", _mark_span, out)


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
            yield i + 1, cell.replace(CODE_SPAN, " ").strip()


def check_file(path, rel_path):
    """Return a list of (rule, line, detail) for one file."""
    with open(path, encoding="utf-8") as handle:
        prose = strip_exempt_regions(handle.read(),
                                     os.path.splitext(path)[1].lower())

    hits = []

    def line_of(offset):
        return prose[:offset].count("\n") + 1

    for rule, pattern in PATTERNS:
        if exemption(rel_path, rule):
            continue
        # Every rule is case-insensitive. The second-person rule was the one
        # exception and the exception cost it its main target: "You" and
        # "Your" opening a sentence are the commonest form the construction
        # takes, and a case-sensitive pattern reads straight past them.
        flags = re.I
        for match in re.finditer(wrap_tolerant(pattern), prose, flags):
            context = prose[max(0, match.start() - 40): match.end() + 40]
            hits.append((rule, line_of(match.start()),
                         " ".join(context.replace(CODE_SPAN, " ").split())))

    if not exemption(rel_path, "question heading"):
        for match in HTML_HEADING.finditer(prose):
            text = TAG.sub("", match.group(1)).replace(CODE_SPAN, " ").strip()
            if label_is_question(text):
                hits.append(("question heading", line_of(match.start()), text))
        for match in MD_HEADING.finditer(prose):
            text = match.group(1).replace(CODE_SPAN, " ").strip()
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
        named = []
        for given in paths:
            full = os.path.abspath(given)
            if os.path.isdir(full):
                # A directory argument expands to the documentation files under
                # it. Passing one used to reach open() and raise
                # IsADirectoryError, which read as a crash rather than as a
                # usable argument.
                for dirpath, _dirnames, filenames in os.walk(full):
                    for name in sorted(filenames):
                        if name.endswith(SUFFIXES):
                            named.append(os.path.join(dirpath, name))
                continue
            named.append(full)
        return sorted(
            ((f, os.path.relpath(f, REPO_ROOT)) for f in named),
            key=lambda pair: pair[1])
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
        print("See ~/.claude/output-styles/technical.md. If a hit is "
              "a verbatim reproduction, add it to EXEMPT with its reason.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
