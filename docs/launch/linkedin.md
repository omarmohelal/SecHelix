# LinkedIn post draft

> **DRAFT — not posted.**

## LinkedIn

> Most security scanners have a failure mode nobody instruments for.
>
> A scanner that crashed, one whose key expired, one that ran out of budget, and
> one that genuinely examined everything and found nothing all produce the same
> artifact: an empty findings list. The CI job goes green either way.
>
> I spent the last weeks building SecHelix around refusing that. If a lane could
> not run, the release gate returns INCOMPLETE and says "No security claim can
> be made from this run" — a blocked verifier can never become a PASS.
>
> Two things I did not expect:
>
> Pointing the tool at its own runner found a path traversal I had written —
> a run id from the command line was joined straight onto a filesystem path.
> Fixed, with regression tests, in the public history.
>
> And planting a fake finding against a deliberately clean file, tagged HIGH and
> CRITICAL, got refuted by the independent verifier — which never saw those
> tags, because they are stripped before handover.
>
> Open source, Apache-2.0. The blind evaluation numbers are published alongside
> what is still unmeasured, because the second list is the one that matters.
>
> github.com/omarmohelal/SecHelix

---
