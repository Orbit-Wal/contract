<!--
Read CONTRIBUTING.md before filling this out. PRs that leave sections below
empty or with placeholder text will be closed without review.
-->

## Issue

Closes #<!-- issue number -->

## Root cause

<!--
What was actually wrong, in your own words — not a restatement of the issue
title. If the issue asked you to make a decision (e.g. "decide X vs Y"),
state the decision and why here.
-->

## What changed and why

<!--
Not a diff summary — GitHub already shows the diff. Explain the reasoning:
why this approach over alternatives, what tradeoffs you accepted or
rejected, and how this maps to every bullet in the issue's Definition of
done.
-->

## Definition of done — addressed item by item

<!-- Copy each bullet from the issue's "Definition of done" and note how your PR satisfies it. -->

- [ ] Item 1: ...
- [ ] Item 2: ...
- [ ] Item 3: ...

## Evidence this actually runs

<!--
Required. Pick whichever applies and paste it inline (not just linked, in
case the link rots):
- Terminal output of the full test run, including your new/updated tests
- Screen recording or before/after screenshots for UI changes
- Logs from a real run (e.g. against testnet), if the issue is network/
  contract-facing
-->

```
paste test/build output here
```

## Tests

<!-- What did you add/change, and what does it actually assert? -->

## Regression check

<!-- What adjacent behavior does this issue call out as needing to keep working, and how did you verify it still does? -->

## Checklist

- [ ] Every Definition of done bullet above is checked and explained, not just checked
- [ ] Evidence block above is filled in with real output, not omitted
- [ ] New/updated tests are included and shown passing
- [ ] No leftover `console.log`/`TODO`/debug code
- [ ] Related/adjacent behavior re-verified, not assumed unaffected
