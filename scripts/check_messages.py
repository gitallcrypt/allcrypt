#!/usr/bin/env python3
"""Find error messages with Rust's line-continuation rule forgotten.

    python3 scripts/check_messages.py

## The bug this exists for

A Rust string literal split across source lines keeps the newline **and
the leading whitespace of every continuation line**, unless each line
ends with a backslash:

```rust
// Wrong: the message reaches the user with 25 spaces in the middle.
format!("A TLS 1.3 record must carry the legacy version
                      {}; this one says {}.", a, b)

// Right.
format!("A TLS 1.3 record must carry the legacy version \\
         {}; this one says {}.", a, b)
```

Nothing notices. It compiles, the message is still "correct", and every
test that looks at it uses `contains` with a substring that does not
straddle the join. It reaches a user as

    ...which this client did not offer - it offered 2 suite(s) - ...
    and every one of them                          needs TLSv1.3 or later

and the user asks what it means, which is how the first one was found.
Five had accumulated by then, in four files, the oldest of them in the
TLS 1.3 record layer.

## What it flags, and what it deliberately does not

A **plain** (non-raw) string literal that:

  * contains no `\\n` and no real newline, so it is prose meant to be one
    line rather than laid-out text;
  * is longer than 40 characters, so short literals with aligned columns
    are left alone;
  * and contains a run of three or more spaces between two non-spaces.

Help text, usage banners and ASCII tables are excluded by the first rule:
they contain `\\n` on purpose. Raw strings (`r"..."`, `r#"..."#`) are
skipped outright, since their whole point is to keep what is written.

Two spaces after a full stop would be a style choice rather than a bug,
so the floor is three. The one place that asserts on this directly -
`tls::client`'s `test_the_message_when_every_offered_suite_needs_a_newer_version`
- is stricter and refuses two, because it knows what its own message
should look like.

This is a lint over source text, not a parser. It tracks quotes,
backslash escapes, line comments and raw strings, which is enough for
this codebase; it is not enough for, say, a `"` inside a nested comment,
and if it ever reports something absurd that is where to look.
"""

from __future__ import annotations

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: Three or more spaces with something either side of them.
RUN_OF_SPACES = re.compile(r"[^ ] {3,}[^ ]")

#: A format spec with a **width or an alignment** in it: `{:11}`,
#: `{:>9.2?}`, `{:<20}`.
#:
#: Such a literal is a table row, where runs of spaces are the column
#: separators and entirely deliberate - `tools/src/bin/bench_ec.rs` and
#: `bench_modpow.rs` print their timings that way, and both were false
#: positives on the first run of this script.
#:
#: **Width or alignment, not any spec.** `{}` and `{:?}` appear in
#: ordinary prose messages, and four of the five real findings used
#: nothing else, so excluding every `{:...}` would have excluded the bugs
#: along with the tables.
ALIGNED_COLUMN = re.compile(r"\{:[^}]*[0-9<>^][^}]*\}")

#: Shorter than this and an aligned literal is more likely than a bug.
SHORTEST = 40


def literals(text):
    """Every plain string literal, as Rust would build it.

    Yields `(line, value)`. The continuation rule is applied: a backslash
    at end of line consumes the newline and the indentation after it, so a
    literal written correctly comes back with single spaces and one
    written wrongly comes back with the run this script is looking for.
    """
    out, index, line = [], 0, 1
    while index < len(text):
        character = text[index]
        if character == "\n":
            line += 1
            index += 1
            continue
        # A line comment can hold anything, including an unbalanced quote.
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        # Raw strings keep their own whitespace on purpose.
        if character == "r" and (text.startswith('r"', index)
                                 or text.startswith("r#", index)):
            if text.startswith('r"', index):
                end = text.find('"', index + 2)
                index = len(text) if end < 0 else end + 1
            else:
                end = text.find('"#', index + 3)
                index = len(text) if end < 0 else end + 2
            continue
        if character == '"':
            start, cursor, value = line, index + 1, []
            while cursor < len(text):
                if text[cursor] == "\\":
                    following = text[cursor + 1] if cursor + 1 < len(text) else ""
                    if following == "\n":
                        # **The rule this script is about.**
                        line += 1
                        cursor += 2
                        while cursor < len(text) and text[cursor] in " \t":
                            cursor += 1
                        continue
                    value.append("\\" + following)
                    cursor += 2
                    continue
                if text[cursor] == '"':
                    break
                if text[cursor] == "\n":
                    line += 1
                value.append(text[cursor])
                cursor += 1
            out.append((start, "".join(value)))
            index = cursor + 1
            continue
        index += 1
    return out


#: `(literal, should_be_flagged)` - the lint against its own history.
#:
#: The first four are the real findings, as they were before the fix; the
#: last three are the false positives the first run produced. A lint with
#: no cases of its own drifts into flagging nothing, and nothing is what
#: it would then report on a clean tree - indistinguishable from working.
SELF_TEST = [
    ("A TLS 1.3 record must carry the legacy version                  "
     "{}; this one says {}.", True),
    ("The client sent more than the {} bytes of early data this       "
     "           ticket allows.", True),
    ("A TLS 1.3 record claims {:?} rather than                        "
     "          application_data.", True),
    ("offered {} suite(s) - {} - and every one of them                "
     "          needs {} or later", True),
    ("{:11}  scalar_mul {:>9.2?}   scalar_mul_ct {:>9.2?}", False),
    ("{:18}  montgomery {:>10.2?}   ladder {:>10.2?}   speedup {:.0}x", False),
    ("a short one   with a run", False),          # under the length floor
]


def self_test():
    """Check the rule against the findings it was written for."""
    for value, expected in SELF_TEST:
        flagged = (len(value) > SHORTEST
                   and not ALIGNED_COLUMN.search(value)
                   and bool(RUN_OF_SPACES.search(value)))
        if flagged != expected:
            raise SystemExit(
                f"the rule has drifted: {value[:60]!r} should "
                f"{'' if expected else 'not '}be flagged")


def main():
    self_test()
    sources = sorted(glob.glob(os.path.join(ROOT, "src", "**", "*.rs"),
                               recursive=True)
                     + glob.glob(os.path.join(ROOT, "tests", "*.rs"))
                     + glob.glob(os.path.join(ROOT, "examples", "**", "*.rs"), recursive=True)
                     + glob.glob(os.path.join(ROOT, "tools", "src", "bin", "*.rs")))
    if not sources:
        sys.exit("no Rust sources found - run this from the repository")

    found = []
    for path in sources:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for line, value in literals(text):
            if "\\n" in value or "\n" in value:
                continue
            if len(value) <= SHORTEST:
                continue
            if ALIGNED_COLUMN.search(value):
                continue
            if RUN_OF_SPACES.search(value):
                found.append((os.path.relpath(path, ROOT), line, value))

    for path, line, value in found:
        print(f"{path}:{line}: a run of spaces inside a one-line message")
        print(f"    {value[:150]!r}")
        print("    Add a `\\` at the end of each continuation line.")
    print(f"\n{len(sources)} files scanned, {len(found)} message(s) with "
          f"baked-in indentation")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
