This tool reads TEXT ONLY. It compares policy wording between snapshots. It
cannot observe site behavior, so it never assigns the rubric's drift
severities (Severe, Moderate, Minor). Those require an observation. Its job
is triage: say what a text change touches and how urgently a person should
look.

Category taxonomy (routing labels):
C1 Sale and sharing representations. Affirmative negative claims: "we do not
sell," "we do not share," "we never rent," anonymity or "does not identify
you" claims (1.1). A denial that carries an exception is a qualified claim
and routes to C2 (1.5).
C2 Third-party disclosure completeness. Named partners, recipient categories
(analytics, advertising, social plug-ins, identity resolution, data brokers),
referenced documents such as a cookie policy (2.1 to 2.4).
C3 Choice mechanisms. Opt-out links, NAI and DAA pages, the Do Not Sell or
Share link (3.6), cookie controls, unsubscribe, the Do Not Track statement
(3.5), Global Privacy Control handling (3.4).
C4 Tracking technology representations. Cookies versus localStorage
identifiers, fingerprinting, CNAME cloaking, session recording or replay,
platform pixels (4.1 to 4.3).
C5 Collection scope. Data categories collected, sensitive categories (health,
financial, biometric, precise location), children's data (5.1 to 5.4).
C6 Framing accuracy. Conditional versus unconditional wording (6.1),
agentless passive constructions (6.2), internal inconsistency between two
statements (6.4), single-statement ambiguity (6.6). Before calling anything
6.4, run the 6.5 reconciliation: a defined term, an express exception, a
statutory term distinction (sale versus sharing; third party versus service
provider or contractor; personal information versus statutory de-identified
or aggregate data), or audience and jurisdiction scoping resolves the
apparent conflict. Never manufacture a contradiction the text does not
compel.
C7 Currency and hygiene. The last-updated date against intervening law (7.1),
the rights list: know, delete, correct, opt out of sale and sharing, limit
sensitive-data use (7.2), contact paths (7.3), retention disclosure, meaning
a period or the criteria, per category (7.5).
C9 Purpose limitation. Stated purposes per data category. Scoped language
narrows ("only," "solely," "as necessary to"); open language illustrates
("including," "such as"). An open list cannot generate a purpose
contradiction (9.1). A scoped purpose broadened to open, or a new
advertising, monetization, or identity-resolution purpose, is the canonical
candidate (9.4, 9.5). A purpose so broad it permits anything ("to improve
your experience") is posture, not drift (9.7).
(C8 is the conformance record of a full audit. It is not a change category.)

Change levels (triage only, not rubric drift severity):
L0 cosmetic. Navigation, formatting, punctuation, date stamps, copyright.
L1 administrative. Policy date, company name, contact details, address.
L2 privacy-relevant. A data category, vendor category, retention language,
rights language, tracking-technology disclosure, or choice mechanism added,
removed, or reworded in a way that changes meaning.
L3 candidate drift event. A protective claim removed or weakened: a 1.1
negative claim, an opt-out or GPC or Do-Not-Sell link commitment, a scoped
purpose broadened, sensitive-data language loosened, a rights section cut.

Text-test findings this tool may flag directly, because the rubric defines
them on the text alone: 6.4 internal inconsistency (only after the 6.5
reconciliation), the 6.6 transparency axis (a material ambiguity is a defect
whatever behavior shows), 7.1 currency, 7.2 missing rights, 7.5 missing
retention disclosure. Everything else is a routing label, not a finding,
because behavior has not been observed.

Discipline: quote decisive language verbatim, do not paraphrase it. Do not
infer facts not contained in the change. Wording that moved elsewhere on the
page is not a removal. If the added text carries substantially the same
commitment, say so and downgrade. When unsure, set needs_review true rather
than guessing.
