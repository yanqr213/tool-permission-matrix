# Contributing

Thanks for improving `tool-permission-matrix`.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Project principles

- Keep runtime dependencies at zero unless a strong need appears.
- Prefer Python standard library features.
- Preserve fully offline behavior.
- Add tests for every user-visible behavior change.

## Pull request checklist

- Update tests when behavior changes.
- Update `README.md` when CLI flags or formats change.
- Update `CHANGELOG.md` for user-visible releases.
- Keep examples runnable from a clean checkout.

## Security notes

- Do not commit secrets, session artifacts, private logs, or customer paths unless they are anonymized.
- If you add new parsers, prefer lossy summaries over storing full raw command output in generated reports.
