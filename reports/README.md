# SecHelix report renderer

`report_renderer.py` derives Markdown, redacted JSON, SARIF 2.1.0, and a
standalone escaped HTML report from one canonical JSON input.

```bash
python -m reports.report_renderer examples/report.example.json --format markdown
python -m reports.report_renderer examples/report.example.json --format json --output report.json
python -m reports.report_renderer examples/report.example.json --format sarif --output report.sarif
python -m reports.report_renderer examples/report.example.json --format html --output report.html
```

The input remains the source of truth. Derived formats do not independently
change status, severity, verification, resolution, or release recommendation.
Secret-bearing keys and common credential patterns are replaced with
`[REDACTED]` in every format. HTML and Markdown render user-controlled text as
text rather than active markup.

The renderer validates the minimum envelope itself so malformed or empty input
cannot be presented as a credible security report. CI may additionally validate
the input against the canonical repository schemas when those are available.
