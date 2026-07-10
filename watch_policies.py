"""Policy Watch. Text-change monitor for the Orion Private watchlist.

A triage layer. It notices when a tracked privacy policy's TEXT changes,
classifies what the change touches using the taxonomy in
standards/drift_rubric_digest.md, and rates urgency on a 0-3 change ladder.
It reads text only. It cannot observe site behavior, so it never assigns
the rubric's drift severities. A Level 3 means "run the full Drift
Assessment," not "drift found."

Setup, one time:
  - Secret: repo Settings -> Secrets and variables -> Actions -> new secret
    named ANTHROPIC_API_KEY.
  - Workflow dependencies: pip install requests trafilatura
  - Workflow permissions: contents: write, issues: write
  - The bot commits: policy-baselines/, policy-fingerprints/,
    policy-reports/, policy-history.json, HISTORY.md
  - Optional: noise_rules.json suppresses known page junk per domain.
  - Optional: companies.json maps watchlist URLs to display names.
"""

import datetime
import difflib
import hashlib
import json
import os
import pathlib
import re
import sys
from urllib.parse import urlparse

import requests

try:
    import trafilatura
except ImportError:
    trafilatura = None

if trafilatura is None:
    sys.exit("trafilatura is required. Add `pip install requests trafilatura` to the workflow.")

API_KEY = os.environ["ANTHROPIC_API_KEY"]
MODEL = "claude-sonnet-4-6"
RUBRIC_VERSION = "1.5"

# Bump this whenever the extraction pipeline changes. A mismatch with the
# stored marker re-seeds every baseline instead of reporting phantom diffs.
EXTRACTOR_VERSION = "2-trafilatura"

today = datetime.date.today().isoformat()

baseline_dir = pathlib.Path("policy-baselines")
baseline_dir.mkdir(exist_ok=True)
fingerprint_dir = pathlib.Path("policy-fingerprints")
fingerprint_dir.mkdir(exist_ok=True)
report_dir = pathlib.Path("policy-reports")
report_dir.mkdir(exist_ok=True)
evidence_dir = report_dir / "evidence" / today
evidence_dir.mkdir(parents=True, exist_ok=True)

# The rubric digest is data, not code. The classifier sees exactly this file.
RUBRIC_PATH = pathlib.Path("standards/drift_rubric_digest.md")
if not RUBRIC_PATH.exists():
    sys.exit("standards/drift_rubric_digest.md is missing. The classifier cannot run without it.")
RUBRIC_DIGEST = RUBRIC_PATH.read_text()


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------

def slug(url):
    return re.sub(r"[^a-zA-Z0-9]+", "_", url)[:120]


def domain(url):
    netloc = urlparse(url if "://" in url else "https://" + url).netloc
    return netloc[4:] if netloc.startswith("www.") else netloc


def sha16(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def tidy(text):
    # Normalize spacing but keep newlines. Newlines are the paragraph
    # boundaries the diff runs on.
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" ?\n ?", "\n", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def fetch(url):
    # The watchlist is never edited. A scheme-less entry gets https://
    # prepended at request time only.
    target = url if "://" in url else "https://" + url
    resp = requests.get(
        target,
        timeout=45,
        headers={"User-Agent": "Mozilla/5.0 OrionPolicyWatch"},
    )
    resp.raise_for_status()
    return resp.text


def extract(html, url):
    # trafilatura isolates the main content and drops navigation, footers,
    # and cookie banners. It is deterministic, which matters, because the
    # baseline must be stable.
    text = trafilatura.extract(
        html,
        url=url,
        include_comments=False,
        include_tables=True,
        favor_precision=True,
    )
    return text.strip() if text else None


def load_noise_rules():
    path = pathlib.Path("noise_rules.json")
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
        return {key: [re.compile(p, re.I) for p in pats] for key, pats in raw.items()}
    except Exception as e:
        print("WARNING: noise_rules.json unreadable, ignoring it: " + str(e), file=sys.stderr)
        return {}


def apply_noise(text, url, rules):
    # Applied in memory only, to both the old and the new text at compare
    # time. Baselines stay raw, so editing a rule never corrupts history.
    for key, patterns in rules.items():
        if key in url:
            for pattern in patterns:
                text = pattern.sub(" ", text)
    return tidy(text)


# Deliberately narrow. Only update stamps and copyright years are blanked.
# A changed number in retention or rights language matches neither pattern
# and still surfaces.
STAMP_PATTERNS = [
    re.compile(
        r"(?i)\b(last\s+(updated|modified|revised|reviewed)|effective\s+date|"
        r"updated\s+on|date\s+of\s+last\s+revision|revision\s+date)\b"
        r"[^\n.]{0,40}?\d{4}"
    ),
    re.compile(r"(?i)(\u00a9|\(c\)|copyright)\s*\d{4}(\s*[-\u2013\u2014]\s*\d{4})?"),
]


def normalize_cosmetic(text):
    for pattern in STAMP_PATTERNS:
        text = pattern.sub("STAMP", text)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# Presentation lookups. Names for people; codes stay primary so the report
# greps the same as the Drift Assessment.
# ---------------------------------------------------------------------------

def load_companies():
    path = pathlib.Path("companies.json")
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as e:
        print("WARNING: companies.json unreadable, ignoring it: " + str(e), file=sys.stderr)
        return {}


COMPANIES = load_companies()


def display_name(url):
    return COMPANIES.get(url) or domain(url)


LEVEL_NAME = {
    0: "cosmetic",
    1: "administrative",
    2: "privacy-relevant",
    3: "candidate drift event",
}

LEVEL_ACTION = {3: "Run Drift Assessment", 2: "Analyst review", 1: "Review optional"}

CATEGORY_NAME = {
    "C1": "sale and sharing claims",
    "C2": "third-party disclosure",
    "C3": "choice mechanisms",
    "C4": "tracking technology",
    "C5": "collection scope",
    "C6": "framing",
    "C7": "currency and hygiene",
    "C9": "purpose limitation",
}


def render_cats(cats):
    parts = []
    for c in cats or []:
        root = str(c).split(".")[0].upper()
        name = CATEGORY_NAME.get(root)
        parts.append(str(c) + " " + name if name else str(c))
    return ", ".join(parts)


def one_line(s):
    return re.sub(r"\s+", " ", str(s or "")).strip()


def plural(n, noun):
    return str(n) + " " + noun + ("" if n == 1 else "s")


# ---------------------------------------------------------------------------
# API calls. Temperature 0 on both, because a nondeterministic classifier
# would invent drift on its own.
# ---------------------------------------------------------------------------

def call_claude(prompt, max_tokens):
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": max_tokens,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=180,
        )
        data = r.json()
        if "error" in data:
            return None, json.dumps(data["error"])
        text = "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        ).strip()
        return text, None
    except Exception as e:
        return None, str(e)


def parse_json(text):
    if not text:
        return None
    cleaned = re.sub(r"```(json)?", "", text).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end + 1])
            except Exception:
                return None
        return None


# ---------------------------------------------------------------------------
# The fingerprint: a structured snapshot of what the policy claims.
# Re-extracted only when the text actually changed, so model nondeterminism
# cannot generate a delta by itself.
# ---------------------------------------------------------------------------

FINGERPRINT_SCHEMA = """{
  "policy_date": "as stated in the text, or null",
  "negative_claims": ["verbatim quotes"],
  "purposes": [{"text": "verbatim quote", "scope": "scoped" or "open"}],
  "data_categories": [],
  "sensitive_categories": [],
  "named_third_parties": [],
  "third_party_categories": [],
  "rights": [],
  "choice_mechanisms": [],
  "retention_disclosure": {"present": true or false, "type": "period" or "criteria" or "none"},
  "dnt_statement": true or false,
  "gpc_mentioned": true or false
}"""


def fingerprint(text):
    prompt = (
        "Extract a policy fingerprint: the textual inventory items from the Orion "
        "Policy Drift Assessment Rubric v" + RUBRIC_VERSION + " (1.1 negative claims, "
        "2.1 named third parties and recipient categories, 3.1 choice mechanisms, "
        "C5 data categories including sensitive ones, 7.2 rights, 7.5 retention "
        "disclosure, 9.1 purposes with their scope). Quote negative claims and "
        "purposes verbatim. Scoped purposes narrow ('only', 'solely', 'as necessary "
        "to'); open purposes illustrate ('including', 'such as'). Do not invent "
        "entries. Empty arrays where the policy is silent.\n\n"
        "Return JSON only, no markdown fences, exactly this schema:\n"
        + FINGERPRINT_SCHEMA
        + "\n\nPOLICY TEXT:\n"
        + text[:80000]
    )
    raw, err = call_claude(prompt, 3000)
    if err:
        print("  fingerprint failed: " + err, file=sys.stderr)
        return None
    return parse_json(raw)


LIST_FIELDS = [
    "negative_claims",
    "data_categories",
    "sensitive_categories",
    "named_third_parties",
    "third_party_categories",
    "rights",
    "choice_mechanisms",
]


def fp_delta(old, new):
    if not old or not new:
        return []
    lines = []
    for field in LIST_FIELDS:
        before = {str(x).strip().casefold(): str(x).strip() for x in old.get(field) or []}
        after = {str(x).strip().casefold(): str(x).strip() for x in new.get(field) or []}
        for key in sorted(set(before) - set(after)):
            lines.append("- " + field + " removed: " + before[key])
        for key in sorted(set(after) - set(before)):
            lines.append("+ " + field + " added: " + after[key])
    before_p = {p.get("text", "").strip().casefold(): p for p in old.get("purposes") or []}
    after_p = {p.get("text", "").strip().casefold(): p for p in new.get("purposes") or []}
    for key in sorted(set(before_p) - set(after_p)):
        lines.append("- purpose removed: " + before_p[key].get("text", ""))
    for key in sorted(set(after_p) - set(before_p)):
        p = after_p[key]
        lines.append("+ purpose added (" + str(p.get("scope", "?")) + "): " + p.get("text", ""))
    for key in sorted(set(before_p) & set(after_p)):
        if before_p[key].get("scope") != after_p[key].get("scope"):
            lines.append(
                "~ purpose scope changed (" + str(before_p[key].get("scope")) + " -> "
                + str(after_p[key].get("scope")) + "): " + after_p[key].get("text", "")
            )
    ret_old = old.get("retention_disclosure") or {}
    ret_new = new.get("retention_disclosure") or {}
    if ret_old != ret_new:
        lines.append("~ retention disclosure: " + json.dumps(ret_old) + " -> " + json.dumps(ret_new))
    for flag in ("dnt_statement", "gpc_mentioned"):
        if old.get(flag) != new.get(flag):
            lines.append("~ " + flag + ": " + str(old.get(flag)) + " -> " + str(new.get(flag)))
    if old.get("policy_date") != new.get("policy_date"):
        lines.append("~ policy_date: " + str(old.get("policy_date")) + " -> " + str(new.get("policy_date")))
    return lines


# ---------------------------------------------------------------------------
# The judge. One call per substantive change, digest pasted in, JSON out.
# ---------------------------------------------------------------------------

JUDGE_SCHEMA = """{
  "level": 0 or 1 or 2 or 3,
  "categories": ["C1.1", "C9.1"],
  "text_test_findings": ["7.5 retention disclosure removed"],
  "summary": "one to three plain sentences saying what shifted",
  "why_it_matters": "one sentence on what the new wording grants, removes, or commits to, drawn from the text, or null",
  "removed_quote": "decisive removed language, verbatim, 40 words max, or null",
  "added_quote": "decisive added language, verbatim, 40 words max, or null",
  "action": "none" or "log" or "analyst_review" or "run_drift_assessment",
  "needs_review": true or false,
  "notes": "uncertainty, a possible service-provider carve-out, moved-not-removed, or null"
}"""


def judge(url, removed, added, delta_lines):
    prompt = (
        "You are the triage classifier for Orion Private's Policy Watch. Apply this "
        "digest.\n\n" + RUBRIC_DIGEST
        + "\n\nA tracked privacy policy's text changed between snapshots.\n\nURL: " + url
        + "\n\nFingerprint delta (structured claims, old versus new):\n"
        + ("\n".join(delta_lines) if delta_lines else "none detected")
        + "\n\nREMOVED paragraphs:\n" + (removed[:6000] or "(nothing removed)")
        + "\n\nADDED paragraphs:\n" + (added[:6000] or "(nothing added)")
        + "\n\nwhy_it_matters states the significance of the wording itself: "
        "discretion granted, a commitment added, removed, or narrowed. It is not "
        "legal advice and draws no compliance conclusions."
        + "\n\nReturn JSON only, no markdown fences, exactly this schema:\n" + JUDGE_SCHEMA
    )
    raw, err = call_claude(prompt, 1000)
    verdict = parse_json(raw)
    if verdict is None or "level" not in verdict:
        return {
            "level": 2,
            "categories": [],
            "text_test_findings": [],
            "summary": "Classifier failed. Raw change preserved in the evidence file.",
            "why_it_matters": None,
            "removed_quote": None,
            "added_quote": None,
            "action": "analyst_review",
            "needs_review": True,
            "notes": (err or raw or "no response")[:400],
        }
    try:
        verdict["level"] = max(0, min(3, int(verdict.get("level", 2))))
    except Exception:
        verdict["level"] = 2
        verdict["needs_review"] = True
    return verdict


def open_issue(title, body):
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return False
    try:
        r = requests.post(
            "https://api.github.com/repos/" + repo + "/issues",
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
            },
            json={"title": title, "body": body, "labels": ["policy-watch"]},
            timeout=30,
        )
        return r.status_code == 201
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main walk.
# ---------------------------------------------------------------------------

# Read the watchlist. Leading bullets and stray whitespace are stripped so a
# reformatted file can never feed "- https://..." into the fetcher again.
lines = pathlib.Path("watchlist.txt").read_text().splitlines()
raw_urls = []
for ln in lines:
    s = ln.strip().lstrip("-*\u2022 ").strip()
    if s and not s.startswith("#"):
        raw_urls.append(s)
urls = list(dict.fromkeys(raw_urls))
duplicates = len(raw_urls) - len(urls)

noise_rules = load_noise_rules()

# Extractor version gate. On mismatch, re-seed everything cleanly.
marker = baseline_dir / ".extractor_version"
stored = marker.read_text().strip() if marker.exists() else ""
reseed = stored != EXTRACTOR_VERSION
if reseed:
    print("Extraction method changed (" + (stored or "none") + " -> "
          + EXTRACTOR_VERSION + "). Re-seeding all baselines this run.")
    marker.write_text(EXTRACTOR_VERSION)

unchanged = 0
cosmetic = []
unreachable = []
new_tracked = []
changes = []

for url in urls:
    name = display_name(url)
    base_path = baseline_dir / (slug(url) + ".txt")
    fp_path = fingerprint_dir / (slug(url) + ".json")

    try:
        html = fetch(url)
    except Exception as e:
        unreachable.append((url, str(e)[:100]))
        continue

    text = extract(html, url)
    if not text or len(text) < 200:
        unreachable.append((url, "page loaded but no main content found, likely JavaScript-rendered"))
        continue
    text = tidy(text)

    if reseed or not base_path.exists():
        base_path.write_text(text)
        fp = fingerprint(text)
        if fp is not None:
            fp_path.write_text(json.dumps(fp, indent=1))
        new_tracked.append(url)
        print("seeded: " + name)
        continue

    old = base_path.read_text()
    old_clean = apply_noise(old, url, noise_rules)
    new_clean = apply_noise(text, url, noise_rules)

    if old_clean == new_clean:
        unchanged += 1
        if old != text:
            base_path.write_text(text)
        continue

    if normalize_cosmetic(old_clean) == normalize_cosmetic(new_clean):
        cosmetic.append((name, "date stamp or copyright only, auto-filtered"))
        base_path.write_text(text)
        continue

    diff = list(difflib.unified_diff(
        [p for p in old_clean.split("\n") if p.strip()],
        [p for p in new_clean.split("\n") if p.strip()],
        lineterm="",
        n=0,
    ))
    removed = "\n".join(l[1:] for l in diff if l.startswith("-") and not l.startswith("---"))
    added = "\n".join(l[1:] for l in diff if l.startswith("+") and not l.startswith("+++"))

    old_fp = parse_json(fp_path.read_text()) if fp_path.exists() else None
    new_fp = fingerprint(text)
    delta = fp_delta(old_fp, new_fp)

    verdict = judge(url, removed, added, delta)

    if verdict["level"] == 0:
        cosmetic.append((name, one_line(verdict.get("summary")) or "judged cosmetic"))
        base_path.write_text(text)
        if new_fp is not None:
            fp_path.write_text(json.dumps(new_fp, indent=1))
        continue

    ev_path = evidence_dir / (slug(url) + ".md")
    ev = []
    ev.append("# Evidence: " + name)
    ev.append("")
    ev.append("- URL: " + url)
    ev.append("- Retrieved: " + today)
    ev.append("- Previous snapshot sha256: " + sha16(old))
    ev.append("- Current snapshot sha256: " + sha16(text))
    ev.append("- Taxonomy: Orion rubric v" + RUBRIC_VERSION + ", extractor " + EXTRACTOR_VERSION)
    ev.append("")
    ev.append("## Verdict")
    ev.append("```json")
    ev.append(json.dumps(verdict, indent=1))
    ev.append("```")
    ev.append("")
    ev.append("## Fingerprint delta")
    ev.extend(delta or ["(none)"])
    ev.append("")
    ev.append("## Removed")
    ev.append("```")
    ev.append(removed[:20000] or "(nothing removed)")
    ev.append("```")
    ev.append("")
    ev.append("## Added")
    ev.append("```")
    ev.append(added[:20000] or "(nothing added)")
    ev.append("```")
    ev_path.write_text("\n".join(ev) + "\n")

    changes.append({
        "url": url,
        "name": name,
        "verdict": verdict,
        "delta": delta,
        "evidence": str(ev_path),
        "old_sha": sha16(old),
        "new_sha": sha16(text),
    })
    base_path.write_text(text)
    if new_fp is not None:
        fp_path.write_text(json.dumps(new_fp, indent=1))
    print("change L" + str(verdict["level"]) + ": " + name)


# ---------------------------------------------------------------------------
# Policy history.
# ---------------------------------------------------------------------------

history_path = pathlib.Path("policy-history.json")
try:
    history = json.loads(history_path.read_text()) if history_path.exists() else []
except Exception:
    history = []

for c in changes:
    v = c["verdict"]
    history.append({
        "date": today,
        "name": c["name"],
        "url": c["url"],
        "level": v["level"],
        "categories": v.get("categories") or [],
        "summary": one_line(v.get("summary")),
    })

if changes:
    history_path.write_text(json.dumps(history, indent=1))

if history:
    by_name = {}
    for h in history:
        by_name.setdefault(h.get("name") or h.get("url", "?"), []).append(h)
    hl = []
    hl.append("# Policy History")
    hl.append("")
    hl.append("Substantive changes (L1 and above) recorded by Policy Watch, newest "
              "first within each company. Cosmetic changes are not recorded. The "
              "structured record is policy-history.json.")
    for nm in sorted(by_name):
        hl.append("")
        hl.append("## " + nm)
        hl.append("")
        for h in sorted(by_name[nm], key=lambda x: x.get("date", ""), reverse=True):
            cats = ", ".join(h.get("categories") or [])
            cat_part = ", " + cats if cats else ""
            hl.append("- " + h.get("date", "?") + " (L" + str(h.get("level", "?"))
                      + cat_part + "): " + (h.get("summary") or ""))
    pathlib.Path("HISTORY.md").write_text("\n".join(hl) + "\n")
    print("Wrote HISTORY.md")


# ---------------------------------------------------------------------------
# The report.
# ---------------------------------------------------------------------------

changes.sort(key=lambda c: (-c["verdict"]["level"], c["name"]))
counts = {n: sum(1 for c in changes if c["verdict"]["level"] == n) for n in (1, 2, 3)}
retrieved = len(urls) - len(unreachable)

out = []
out.append("# Policy Watch: " + today)
out.append("")
out.append("Automated draft. No analyst has reviewed this report yet.")
out.append("")
out.append("Analyst sign-off: ____________________  Date: ____________")
out.append("")
out.append("Levels below are triage ratings for changed text, not the drift "
           "severities in the Orion Policy Drift Assessment Rubric v" + RUBRIC_VERSION
           + ", which require observed site behavior. This monitor reads text only. "
           "L1 is administrative, L2 is privacy-relevant and goes to analyst review, "
           "L3 is a candidate drift event and triggers the full Drift Assessment. "
           "An L3 means run the assessment, not that drift was found.")
out.append("")
out.append("## Summary")
out.append("")
if counts[3]:
    top = changes[0]
    tv = top["verdict"]
    rc = render_cats(tv.get("categories"))
    cat_part = " (" + rc + ")" if rc else ""
    if counts[3] == 1:
        out.append("One candidate drift event this run: " + top["name"] + cat_part
                   + ". " + one_line(tv.get("summary")))
    else:
        out.append(plural(counts[3], "candidate drift event") + " this run. Most "
                   "significant: " + top["name"] + cat_part + ". " + one_line(tv.get("summary")))
    if counts[2]:
        out.append("")
        out.append("Also awaiting analyst review: " + plural(counts[2], "privacy-relevant change") + ".")
elif counts[2]:
    top = changes[0]
    out.append("No candidate drift events. Awaiting analyst review: "
               + plural(counts[2], "privacy-relevant change") + ", led by "
               + top["name"] + ": " + one_line(top["verdict"].get("summary")))
elif counts[1]:
    out.append("No privacy-relevant changes across " + str(retrieved) + " retrieved "
               "policies. " + plural(counts[1], "administrative update") + " recorded. "
               "No action required.")
else:
    out.append("No substantive changes across " + str(retrieved) + " retrieved "
               "policies. No action required.")
if unreachable:
    out.append("")
    unread = str(len(unreachable)) + (" policy" if len(unreachable) == 1 else " policies")
    out.append(unread + " could not be read this run; see coverage limitations.")
out.append("")
out.append("## Coverage")
out.append("")
dup_note = " (" + str(duplicates) + " exact duplicate watchlist lines collapsed)" if duplicates else ""
out.append("- Watchlist entries checked: " + str(len(urls)) + dup_note)
out.append("- Retrieved: " + str(retrieved) + " of " + str(len(urls)))
out.append("- Substantive changes: " + str(len(changes))
           + " (L3: " + str(counts[3]) + ", L2: " + str(counts[2]) + ", L1: " + str(counts[1]) + ")")
out.append("- Cosmetic only: " + str(len(cosmetic)) + ". Unchanged: " + str(unchanged)
           + ". Newly tracked: " + str(len(new_tracked)) + ". Unreachable: " + str(len(unreachable)) + ".")
out.append("")

if changes:
    out.append("## Review queue")
    out.append("")
    out.append("| Level | Company | Categories | What shifted |")
    out.append("|---|---|---|---|")
    for c in changes:
        v = c["verdict"]
        cats = ", ".join(v.get("categories") or []) or "-"
        summary = one_line(v.get("summary")).replace("|", "/")[:160]
        out.append("| L" + str(v["level"]) + " | " + c["name"] + " | " + cats + " | " + summary + " |")
    out.append("")
    out.append("## Changes")
    for c in changes:
        v = c["verdict"]
        out.append("")
        out.append("### " + c["name"] + " (L" + str(v["level"]) + ", " + LEVEL_NAME[v["level"]] + ")")
        out.append("")
        out.append("Source: <" + c["url"] + ">")
        out.append("")
        out.append(one_line(v.get("summary")))
        if v.get("why_it_matters"):
            out.append("")
            out.append("**Why it matters:** " + one_line(v["why_it_matters"]))
        if v.get("categories"):
            out.append("")
            out.append("**Categories:** " + render_cats(v["categories"]))
        if v.get("text_test_findings"):
            out.append("")
            out.append("**Text-test findings:** " + "; ".join(v["text_test_findings"]))
        if v.get("removed_quote"):
            out.append("")
            out.append("**Removed:** \"" + one_line(v["removed_quote"]) + "\"")
        if v.get("added_quote"):
            out.append("")
            out.append("**Added:** \"" + one_line(v["added_quote"]) + "\"")
        if c["delta"]:
            out.append("")
            out.append("**Fingerprint delta:**")
            out.append("```")
            out.extend(c["delta"])
            out.append("```")
        out.append("")
        review_note = ", needs human review" if v.get("needs_review") else ""
        out.append("**Action:** " + LEVEL_ACTION[v["level"]] + review_note)
        if v.get("notes"):
            out.append("")
            out.append("**Notes:** " + one_line(v["notes"]))
        out.append("")
        out.append("Snapshots " + c["old_sha"] + " -> " + c["new_sha"]
                   + ". Evidence: `" + c["evidence"] + "`")
else:
    out.append("No substantive policy changes detected this run.")

if cosmetic:
    out.append("")
    out.append("## Cosmetic-only changes")
    out.append("")
    for nm, note in cosmetic:
        out.append("- " + nm + ": " + note)

if new_tracked:
    out.append("")
    out.append("## Newly tracked")
    out.append("")
    seed_note = ("Baseline and fingerprint saved. Watching begins next run."
                 + (" All baselines were re-seeded this run because the extraction method changed."
                    if reseed else ""))
    out.append(seed_note)
    for u in new_tracked:
        out.append("- " + display_name(u) + ": " + u)

out.append("")
out.append("## Coverage limitations")
out.append("")
if unreachable:
    out.append(str(len(unreachable)) + " of " + str(len(urls)) + " monitored policies could "
               "not be read this run. Unreachable is data, not failure: JavaScript "
               "rendering, bot protection, geo walls, and PDF-only policies all land here.")
    out.append("")
    for u, reason in unreachable:
        out.append("- " + display_name(u) + ": " + u + " (" + reason + ")")
else:
    out.append("All monitored policies were retrieved this run.")

out.append("")
out.append("## Method notes")
out.append("")
out.append("Client-fetched text only, from a single US vantage, at a single point in "
           "time. Site behavior, server-side transfers, and contractual terms are "
           "invisible to this monitor, so nothing here is a drift finding under the "
           "rubric. HISTORY.md carries the accumulated change record per company, and "
           "baselines are versioned in git; `git log -p policy-baselines/<file>.txt` "
           "shows the full text history for any entry.")

report_path = report_dir / ("watch-" + today + ".md")
report_path.write_text("\n".join(out) + "\n")
print("Wrote " + str(report_path))


# ---------------------------------------------------------------------------
# Review queue: file an issue for anything Level 2 or higher.
# ---------------------------------------------------------------------------

for c in changes:
    v = c["verdict"]
    if v["level"] < 2:
        continue
    cats = ", ".join(v.get("categories") or []) or "policy change"
    title = "[L" + str(v["level"]) + "] " + c["name"] + ": " + cats
    body = [
        one_line(v.get("summary")),
    ]
    if v.get("why_it_matters"):
        body.append("")
        body.append("Why it matters: " + one_line(v["why_it_matters"]))
    body += [
        "",
        "URL: " + c["url"],
        "Evidence: `" + c["evidence"] + "`",
    ]
    if v.get("removed_quote"):
        body.append("Removed: \"" + one_line(v["removed_quote"]) + "\"")
    if v.get("added_quote"):
        body.append("Added: \"" + one_line(v["added_quote"]) + "\"")
    body += [
        "",
        "Automated draft. Verify against the live policy before acting.",
        "",
        "- [ ] Reviewed",
        "- [ ] Confirmed",
        "- [ ] False positive (recurring? add a noise rule)",
        "- [ ] Escalated to Drift Assessment",
    ]
    if open_issue(title, "\n".join(body)):
        print("issue filed: " + title)

print("Checked " + str(len(urls)) + ". Changed " + str(len(changes))
      + ". Cosmetic " + str(len(cosmetic)) + ". Unchanged " + str(unchanged)
      + ". New " + str(len(new_tracked)) + ". Unreachable " + str(len(unreachable)) + ".")
