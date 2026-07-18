# Contributing to GlobeWallet

This is a real wallet handling real secret key material and real money movement.
The bar for a merged PR here is deliberately high. Read this fully before opening one.

## What "done" means

Every open issue has a **Definition of done** section. That list is not a
menu — it is the acceptance criteria in full. A PR that satisfies two out of
three bullets is not partial credit, it's a different, unfinished issue. If
you believe a bullet is wrong or out of scope, say so explicitly in the PR
description and argue why — don't silently drop it.

PRs that are cosmetic, a one-line config flip, a `// TODO` left in place of
the actual fix, or a change that "should work" but was never run, will be
closed without merge. This project does not accept partial fixes to
security- or correctness-sensitive issues (most of them are).

## What every PR must include

1. **Root-cause explanation.** Not "fixed the bug" — what was actually
   wrong, why it was wrong, and why your fix is the correct one rather than
   a workaround. If the issue asks for a design decision (many do — e.g.
   "decide X vs Y and document it"), that decision and its rationale must be
   written out in the PR description, not just implied by the code.

2. **Evidence the code actually runs.** Claims are not evidence. Include at
   least one of:
   - Pasted terminal output of the test suite passing (`npm test`,
     `cargo test`, etc. — whatever the repo uses), including the new/updated
     tests your change added.
   - For anything with a UI: a screen recording or before/after screenshots
     of the actual behavior on a real simulator/device/browser.
   - For anything network- or contract-facing: logs from a real run against
     testnet (Horizon/Soroban RPC), not a mocked call — unless the issue
     explicitly says mocking is acceptable.
   A PR with no runnable evidence attached will be sent back before review,
   not reviewed and rejected — don't spend review-cycle time on it.

3. **Tests.** If the issue's Definition of done says "test asserting X" or
   "test coverage for Y," that test must exist in the diff and must fail on
   `main` before your fix and pass after it. Screenshot or paste the
   red→green transition if it's not obvious from the diff alone.

4. **No regressions in adjacent behavior.** Several issues explicitly call
   out a related feature that must keep working (e.g. "no regression to the
   happy path for X"). Verify that path too, and say how you verified it.

## Scope expectations

Look at the issue's own framing before starting. Several issues are
explicitly about producing a **decision and design document** first
(threat models, migration strategies, cross-repo interface contracts) —
for those, the write-up itself is the deliverable and needs to be as
rigorous as code would be: concrete failure scenarios, alternatives
considered, and why the chosen approach wins. Don't skip straight to code
for these; a design decision made silently in code, with no written
rationale, does not satisfy the issue.

For issues that are implementation work, expect to touch more than one
file: these issues were written against real architectural gaps (missing
persistence, missing auth, missing on-chain integration), not isolated
one-liners. If your diff is a handful of lines against an issue like that,
you've probably solved a symptom, not the issue.

## Before you open the PR

- [ ] Every Definition of done bullet addressed, with a one-line note per
      bullet on how (in the PR description)
- [ ] Root cause and rationale written out, not just "fixed"
- [ ] Runnable evidence attached (test output, logs, or recording)
- [ ] New/updated tests included and shown passing
- [ ] Adjacent/related behavior called out in the issue re-verified
- [ ] No stray `console.log`/`TODO`/commented-out code left from debugging

PRs missing these will get a single comment pointing back here, not a
detailed review — please do this up front so review time goes to the
substance of the change.
