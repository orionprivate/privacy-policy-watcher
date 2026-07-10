# privacy-policy-watcher
# Policy Watch

A weekly monitor of privacy-policy changes across ~100 companies, published by [Orion Private](https://orionprivate.com). Each run fetches every tracked policy, detects text changes against the prior snapshot, classifies what each change touches, and rates how urgently a person should look.

## How it works

A GitHub Actions workflow runs weekly. `watch_policies.py` loads the drift taxonomy, fetches each policy, extracts the readable text, and compares it to the stored baseline. A changed policy is diffed, re-fingerprinted, and sent to Claude for classification. Every alert is a draft reviewed by a human before it means anything. Nothing here is a legal conclusion.

The taxonomy is data, not code. The pipeline reads it at run time from `standards/`, so a change to the rubric never requires a code change.

## What it is, and is not

This monitor reads text only. It sees what a privacy policy says, not what a site does. It therefore never issues the drift severities of the Orion Policy Drift Assessment Rubric, which require observed site behavior. It assigns a triage level (L0 cosmetic to L3 candidate drift event) and routes each change to rubric categories C1 through C9. An L3 means run the full Drift Assessment, not that drift was found.

## Repository map

