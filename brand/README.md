# goSignals — Brand Assets

The official mark, badge, and lockup files. Drop-in ready for use by Claude
Code or any web project.

The recommended primary mark is the **stream badge**: the routing-mark logo
layered on a 6-line in-phase sine-wave field — a nod to phosphor scan lines.
It sits to the left of the wordmark in the standard lockup.

```
brand/
├── tokens.css                       Color + font tokens (use these — don't hard-code)
├── components/
│   └── GoSignalsLogo.jsx            React component (default export: GoSignalsLockup)
├── logo/
│   ├── gosignals-badge-primary.svg          ★ PRIMARY  (white mark · phos border · black fill)
│   ├── gosignals-badge-no-border.svg          Primary minus the border
│   ├── gosignals-badge-mono-phos.svg          All phosphor — for places color is restricted
│   ├── gosignals-badge-mono-white.svg         All white — for two-color print
│   ├── gosignals-badge-mint-accent.svg        Mint mark variant
│   ├── gosignals-badge-on-light.svg           Ink on white — for light backgrounds
│   ├── gosignals-badge-on-cream.svg           Ink on #f6f4ef cream
│   ├── gosignals-lockup-primary.svg         ★ PRIMARY  (badge + wordmark, dark)
│   ├── gosignals-lockup-mono-phos.svg
│   ├── gosignals-lockup-on-light.svg
│   ├── gosignals-mark-phos.svg                Routing mark only, phosphor
│   ├── gosignals-mark-white.svg               Routing mark only, white
│   ├── gosignals-mark-ink.svg                 Routing mark only, ink (for light bg)
│   ├── gosignals-favicon.svg                  Badge at favicon scale (waves still drawn)
│   └── gosignals-favicon-simple.svg           No waves — sharpest at 16/32 px
└── index.html                       Preview page (open to see everything)
```

## Color palette

Defined in `tokens.css`. **Hex values are listed once here**; use the CSS
variables in implementation.

| Token             | Hex       | Use                                              |
|-------------------|-----------|--------------------------------------------------|
| `--gs-bg`         | `#000000` | Canvas / badge fill                              |
| `--gs-phos`       | `#6BE49A` | Primary phosphor accent · "Signals" half of wordmark |
| `--gs-phos-dim`   | `#2E7C4A` | Borders, waves, eyebrow labels                   |
| `--gs-mint`       | `#B8FFC4` | Highlight phosphor                               |
| `--gs-amber`      | `#F5B544` | Warning / alt accent                             |
| `--gs-cyan`       | `#6DB4FF` | Info / alt accent                                |
| `--gs-white`      | `#FFFFFF` | Mark · "go" half of wordmark                     |
| `--gs-text`       | `#d9e6dc` | Body text on dark                                |
| `--gs-text-dim`   | `#7a8a7c` | Secondary text on dark                           |
| `--gs-ink`        | `#0A1A0E` | Mark color on light backgrounds                  |
| `--gs-phos-deep`  | `#0d6d36` | Phosphor on light backgrounds (AA contrast)      |
| `--gs-sage`       | `#7DBA8C` | Waves on light backgrounds                       |
| `--gs-cream`      | `#f6f4ef` | Cream surface                                    |

## Typography

- **Display / Wordmark:** `JetBrains Mono`, weight 500, letter-spacing −0.01em.
  Render via `var(--gs-font-display)`.
- **UI body:** `Inter`, system fallbacks. Render via `var(--gs-font-body)`.

The wordmark is **two-tone**: `<span>go</span>` in white (or ink on light) +
`<span>Signals</span>` in phosphor (or deep phosphor on light). Keep the
casing exactly: lower-case `go`, capital `S`, rest lower-case.

## Usage — React

```jsx
import "./brand/tokens.css";
import {
  GoSignalsBadge,
  GoSignalsLockup,
  GoSignalsMark,
  GOSIGNALS_COLORS,
} from "./brand/components/GoSignalsLogo";

// Header lockup
<GoSignalsLockup size={48} />

// Just the badge
<GoSignalsBadge size={64} variant="primary" />

// On a light page
<GoSignalsLockup size={48} variant="on-light" />

// Tiny — drop the waves for sharpness
<GoSignalsBadge size={20} simplified />

// Just the routing mark
<GoSignalsMark size={32} color={GOSIGNALS_COLORS.PHOS} />
```

### `GoSignalsBadge` props

| Prop          | Default     | Notes                                                        |
|---------------|-------------|--------------------------------------------------------------|
| `size`        | `64`        | Edge length in px. Always renders square.                    |
| `variant`     | `"primary"` | `primary`, `mono-phos`, `mono-white`, `mint-accent`, `on-light`, `on-cream`, `no-border`. |
| `simplified`  | `false`     | Drop the wave field. Use under ~28 px for sharpness.         |
| `title`       | `"goSignals"` | `aria-label` / `<title>`.                                   |

### `GoSignalsLockup` props

| Prop          | Default     | Notes                                                        |
|---------------|-------------|--------------------------------------------------------------|
| `size`        | `48`        | Badge edge length in px. Wordmark scales proportionally.     |
| `variant`     | `"primary"` | Same set as `GoSignalsBadge`.                                |
| `gap`         | `0.28`      | Gap between badge and wordmark, as fraction of `size`.       |

## Usage — vanilla HTML

```html
<link rel="stylesheet" href="brand/tokens.css">

<!-- Inline use — fast, no layout shift -->
<img src="brand/logo/gosignals-lockup-primary.svg" height="48" alt="goSignals">

<!-- Favicon -->
<link rel="icon" type="image/svg+xml" href="brand/logo/gosignals-favicon.svg">
```

## Sizing guidance

| Context           | Recommended size | Variant                                |
|-------------------|------------------|----------------------------------------|
| App header        | 32–48 px         | `primary` lockup                       |
| Hero / splash     | 96–160 px        | `primary` badge                        |
| Footer            | 24 px            | `mono-phos` or `mono-white` lockup     |
| Favicon (32 px)   | —                | `gosignals-favicon-simple.svg`         |
| Touch icon (180+) | —                | `gosignals-favicon.svg`                |
| Print / mono      | —                | `mono-white` on dark, `on-light` on white |

Minimum size for the badge with waves visible: **28 px**. Below that, use the
`simplified` prop (or `gosignals-favicon-simple.svg`) to drop the waves.

## Clear space

Leave at least one badge-stroke-unit of clear space around the lockup on all
sides. That's roughly `size × 0.12` in px.

## Don'ts

- Don't recolor the mark to colors outside the palette.
- Don't rotate or skew the badge.
- Don't separate the wordmark halves with extra space or punctuation.
- Don't place the primary (dark) badge on a phosphor-green field — use
  `mono-phos` or `on-light` instead.
- Don't add a drop shadow or glow to the badge. The wave field is the
  atmosphere.

## Construction

The mark is built on an 8-unit grid in a 64×64 frame:

- 1 signal input on the left
- 1 fork node (filled circle, 7-unit diameter)
- 3 output branches, ending in 6×6 terminals at the right edge
- Strokes are 2.5–2.8 units wide, 90° corners, square line caps

The stream field beneath is 6 in-phase sine waves with amplitude 2.6 and
wavelength 22, drawn in dim phosphor. The mark carries a knockout outline
(stroke matching the badge fill) so it never visually intersects the waves.
