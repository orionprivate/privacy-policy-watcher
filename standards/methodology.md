# Methodology

Policy Watch monitors what privacy policies say, week over week. It is the
trigger layer for the Orion Policy Drift Assessment, not the assessment
itself.

What it tests. The published text of each policy on the watchlist. A change
is diffed at the paragraph level, mapped to the rubric categories C1 through
C9, and rated L0 through L3 for urgency. Five rubric items are pure text
tests and may be flagged directly: 6.4 internal inconsistency, the 6.6
transparency axis, 7.1 currency, 7.2 missing rights, 7.5 missing retention
disclosure.

What it cannot claim. Site behavior, server-side transfers, and contracts
are invisible to this monitor. It therefore never finds drift, which is a
gap between representation and observed behavior. An L3 rating means the
change warrants a full Drift Assessment.

Coverage. Some policies are unreachable in any given run: JavaScript
rendering, bot protection, geo walls, PDF-only policies. Unreachable is
reported as a coverage limitation, never hidden.

Review. Every report is an automated draft until a human signs it. Alerts at
L2 and above are filed for analyst review. False positives are recorded and,
where recurring, suppressed by a named noise rule so the suppression itself
is documented.
