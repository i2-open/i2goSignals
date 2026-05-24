# Keycloak Themes for GoSignals

This directory contains reusable Keycloak login themes styled to match the two skins shipped by the GoSignals admin SPA:

- **`gosignals-mui/`** — MUI / "studio" skin (PRD #39 design tokens). Dark MUI palette by default, light variant via `prefers-color-scheme`.
- **`gosignals-console/`** — phosphor‑CRT "console" skin (PRD #67). Near‑black surfaces, bright phosphor‑green accents, JetBrains Mono everywhere, zero corner radius, phosphor glow chrome, faint scan‑line overlay in dark mode.

Both themes are self‑contained and can be copied into any Keycloak deployment. No Docker Compose is included here by design.

## Contents

Each theme directory contains:

- `theme.properties` — theme metadata (extends Keycloak's `keycloak.v2` parent, registers the stylesheet, declares `kcDarkModeClass`)
- `login/theme.properties` — login‑type metadata
- `login/login.ftl`, `login/template.ftl` — small template overrides so the realm name + logo render above the form in a single centred column
- `login/resources/css/theme.css` — skin‑specific styling (colors, typography, buttons, inputs, alerts, layout overrides)
- `login/resources/img/logo.svg` — the goSignals badge sized for the login card. Pixel‑traced from `src/components/brand/GoSignalsBadge.tsx` in the admin SPA so the mark on the sign‑in page matches the one in the app shell.

Templates only carry the realm‑name / logo composition we want above the form; everything else comes from Keycloak's defaults so the themes stay compatible with modern Keycloak versions without ongoing template maintenance.

## How to use in another project

1. Copy one (or both) of the theme folders to your Keycloak installation under `themes/`:

   - Keycloak (Quarkus) distribution on a host:
     - Place at: `<keycloak-home>/themes/gosignals-mui` and/or `<keycloak-home>/themes/gosignals-console`
   - Containerized Keycloak:
     - Mount into the container at `/opt/keycloak/themes/gosignals-mui` and/or `/opt/keycloak/themes/gosignals-console`

2. Enable a theme in your realm:

   - Open Keycloak Admin Console for your realm
   - Go to: Realm Settings → Themes
   - Set "Login Theme" to `gosignals-mui` (for the MUI skin) or `gosignals-console` (for the phosphor‑CRT skin)
   - Save

3. (Optional) Development tips

   - Disable theme caching while iterating styles:
     - Admin Console → Realm Settings → Themes → Turn off caching, or
     - Start Keycloak with `--spi-theme-static-max-age=-1 --spi-theme-cache-themes=false --spi-theme-cache-templates=false`
   - Replace `resources/img/logo.svg` with your product logo. The CSS scales it appropriately.

## Customizing colors

Each theme exposes its palette as CSS variables at the top of `login/resources/css/theme.css`:

- `gosignals-mui` — `--mui-*` vars track `src/variables.json` in the admin SPA (the default skin's token layer).
- `gosignals-console` — `--con-*` vars track `src/variables.console.json` (the phosphor‑CRT skin). Brand badge ink is also pinned in `login/resources/img/logo.svg` and should be updated alongside the CSS if you re‑brand.

Update the variables to match your brand and the rest of the styles will follow automatically.

## Scope and compatibility

- Theme type: `login` (neither theme modifies the Admin Console or Account Console)
- Parent: `keycloak.v2` — HTML templates are the Keycloak defaults except for `login.ftl` and `template.ftl`, which only adjust where the realm name + logo render
- Tested with recent Keycloak versions that ship the Quarkus distribution (PatternFly v5 chrome)
