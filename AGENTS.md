# sfrbox-api

Async Python client for the local XML API of SFR boxes (`/api/1.0/?method=...`),
with a minimal `sfrbox-api` CLI. Its main consumer is the Home Assistant
`sfr_box` integration.

## Commands

```console
uv sync --all-extras                       # install (dev + docs groups by default)
npm ci                                     # install prettier (Node version in .nvmrc)
uv run pytest                              # tests
uv run ty check src tests docs/conf.py     # type checking
uv run prek run --all-files                # ruff, prettier, codespell, yamllint, zizmor, ...
uv run sphinx-build docs docs/_build       # docs (Python 3.14+ only)
```

CI runs the same commands with `--locked`; keep `uv.lock` in sync with
`pyproject.toml`.

## Layout

- `src/sfrbox_api/bridge.py`: `SFRBox`, one method per API call
  (e.g. `dsl_get_info` for `dsl.getInfo`), token authentication and XML
  parsing with `defusedxml`.
- `src/sfrbox_api/models.py`: mashumaro dataclasses, one per response element.
- `src/sfrbox_api/cli/`: click CLI (entry point only for now).
- `tests/fixtures/`: recorded XML responses, named `<method>.xml`, with a
  suffix for firmware-specific variants (e.g. `system.getInfo.3_5_8.xml`).
- `docs/`: Sphinx with MyST Markdown.

## Conventions

- Python 3.10+ (`target-version = "py310"`); don't use newer syntax.
- Ruff with `force-single-line` imports and Google-style docstrings, line
  length 80. Existing docstrings are in French; codespell ignores those words
  in `[tool.codespell]`.
- 100% test coverage is required (enforced by covdefaults); add tests with
  every change.
- Tests mock HTTP with aiointercept against the `sfrbox.test` host:
  aiointercept doesn't intercept IP literals, so don't use `192.168.x.x`.
- Dependency floors (`aiohttp`, `mashumaro`, ...) must stay compatible with
  Home Assistant core. Don't raise them without checking HA.
- Fixtures must be anonymised: no real MAC addresses, serial numbers, IP
  addresses, WiFi keys or phone numbers.

## AI policy

This project follows the [AI Policy](AI_POLICY.md). Autonomous contributions
are not accepted: a human must review, understand, and be able to explain
every change before it is submitted. Do not open issues or pull requests
autonomously, and do not post comments on behalf of a user without their
review.
