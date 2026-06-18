# M&S Board Deck Template

Reusable, single-file HTML slide deck in M&S branding. Designed for board packs, Steerco updates and executive briefings — any topic, not just firewall policy.

## Files

- [board-deck-template.html](board-deck-template.html) — the template, with `{{PLACEHOLDER}}` markers throughout.

## How to use

1. Copy the template:
   ```bash
   cp templates/board-deck-template.html board-deck-<topic>-<yyyy-mm-dd>.html
   ```
2. Open the copy and replace every `{{PLACEHOLDER}}`. The most important ones:
   - `{{DECK_TITLE}}`, `{{SUBTITLE}}`, `{{DEPARTMENT}}`, `{{TEAM}}`
   - `{{AUDIENCE}}`, `{{DATE}}`, `{{DECISION_HEADLINE}}`, `{{SCOPE_ONE_LINE}}`
   - `{{TOTAL}}` — total number of slides (default 12). If you change the slide count, also update the per-slide `X / {{TOTAL}}` numbers.
3. Add or remove `<section class="slide">` blocks as needed. Renumber the footer counters and the `<h2 class="section"><span class="num">NN</span>` labels.
4. Open in a browser:
   - **Present:** click *Present* (or press `P`). Navigate with `←` / `→` / `Space` / `PgUp` / `PgDn`. `Home` / `End` jump to first / last. `Esc` to exit.
   - **PDF:** click *Print* (or `⌘P` / `Ctrl+P`). Prints one slide per A4 landscape page with all chrome hidden.

## Slides included

| # | Type | Purpose |
|---|------|---------|
| 1 | Title slide | Deck title, status pill, audience/date/decision/scope |
| 2 | Headline + 3 KPI tiles | One-paragraph summary plus three big numbers |
| 3 | Business impact (Time / Money) | The ROI slide — keep this; it carries the value case |
| 4 | Narrative bullets | "What we built" / "What we did" |
| 5 | Concept (4-card panel) | E.g. "How X acts as a guardrail" |
| 6 | Evidence table | Findings, results (with RAG pills), so-what |
| 7 | Goals table | G1–G5 with KPI, target, owner |
| 8 | Delivery timeline | Phases, dates, owners + critical-path callout |
| 9 | Status / RAG | Workstream-level RAG with notes |
| 10 | RAID | Risks, issues, dependencies |
| 11 | Decision ask | Approve / Fund / Mandate / Endorse / Nominate |
| 12 | Closing slide | Deep-green background, one-sentence summary |

## Brand palette

Aligned with the M&S master brand on [marksandspencer.com](https://www.marksandspencer.com/) — monochrome black & white, light-grey surfaces, RAG used only for semantic status.

| Use | Colour |
|-----|--------|
| Primary (header stripe, brand mark, accents) | `#000000` |
| Heading / hover (near-black) | `#1a1a1a` |
| Deep accent (table headers, closing slide) | `#000000` |
| Body ink | `#111111` / `#1a1a1a` |
| Secondary text | `#595959` |
| Soft surface (zebra rows, KPI tile, callouts) | `#f5f5f5` |
| Rule / border | `#e5e5e5` |
| RAG green | `#00703C` |
| RAG amber | `#C98A00` |
| RAG red | `#B3261E` |

Defined as CSS variables at the top of the template — change them once to re-skin the whole deck. Variable names (`--ms-green`, `--ms-green-dark`, `--ms-green-deep`) are kept from the earlier draft for backwards compatibility; their values are now monochrome.

## Notes

- Self-contained: no external CSS, JS or fonts. Safe to email or host anywhere.
- Slide canvas is 1280×720 (16:9). Presenter mode auto-scales to the viewport.
- `tbody tr:nth-child(even)` gives soft-green zebra rows on every table.
- For a one-off override, you can drop `td.rag-g`, `td.rag-a`, `td.rag-r` into a status cell.

## Reference example

The Firewall Policy Compliance Service board deck — [board-deck.html](../board-deck.html) — is built from this template and shows how the placeholders look populated end-to-end.
