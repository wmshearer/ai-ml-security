# Screenshots — AI Red Team Harness walkthrough

Captures taken while performing `docs/WALKTHROUGH.md`.

## Naming

`NN-short-description.png`, numbered to match the walkthrough step.

Zero-padded so they sort correctly (`01`, not `1`). Lowercase, hyphens, no spaces —
spaces in filenames break shell commands and Markdown image links.

## The shot list

The four that carry the story are marked **★**. If a step produces nothing visually
interesting, skip it — a screenshot of a `cd` command is noise.

| File | Step | What to capture | What to box |
|---|---|---|---|
| `01-setup-tests-passing.png` | Setup 7 | `pytest` output | `99 passed` |
| `02-services-started.png` | 2 | Both uvicorn services up | the two `Uvicorn running on ...` lines |
| `03-normal-question.png` | 3 | The password-reset reply | `"tool_calls_made": []` — empty, took no action |
| `04-the-attack.png` ★ | 4 | Full attack response | the canary in the reply **and** `"status": "sent"` |
| `05-garak-blind-spot.png` ★ | 5 | garak's field list | `tool_calls_made present: False` |
| `06-authz-code.png` | 6 | `src/target/authz.py` in an editor | the allow-list constants |
| `07-guardrail-denies.png` ★ | 7 | Same attack, guarded | `"error": "unauthorized"` and the reason string |
| `08-the-ledger.png` ★ | 8 | The database query output | ALLOWED and DENIED lines together |

If you keep only two: **05** and **08**. Five is the discovery, eight is the proof.

## Taking them

```bash
ksnip
```

Capture a region, annotate in the editor that opens, save. Set the default folder once under
Options → Preferences → Saver so you stop seeing a file dialog.

Tools: rectangle, ellipse, arrow, line, text, marker, blur. Blur is worth knowing about — use
it on anything in the terminal prompt you would rather not publish.

**Do not use flameshot on this machine**, even though it is installed. v14 depends on the XDG
desktop portal, which XFCE does not implement for screenshots; it times out after 30 seconds
and silently aborts. Verified, not assumed.

## Before you capture

- **Widen the terminal** so JSON output does not wrap. Wrapped output is hard to read in a
  screenshot and makes the boxes look messy.
- **Increase the font size** (`Ctrl +` in most terminals). What is comfortable at arm's length
  is unreadable when someone views the image on a laptop.
- **Check the prompt line** for anything you would rather not publish — hostname, full paths,
  other project names. Flameshot's blur tool handles anything you miss.
- **One idea per capture.** Two boxes is usually the limit before a reader stops knowing where
  to look.

## Nothing here is sensitive

`CANARY-SECRET-a7f3d9` is a fake credential planted deliberately so leaks are visible. It is
supposed to appear in these images. There are no real secrets in this project — no API keys,
no tokens, no personal data. Verified before publication.
