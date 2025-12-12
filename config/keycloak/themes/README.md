# Keycloak Material-UI Theme

This directory contains a reusable Keycloak login theme styled to resemble this project's Material‑UI (MUI) look and feel.

The theme is self‑contained and can be copied into any Keycloak deployment. No Docker Compose is included here by design.

## Contents

- `gosignals-mui/` — the theme directory you copy into Keycloak's `themes/` folder
  - `theme.properties` — theme metadata (extends Keycloak base theme, registers our stylesheet)
  - `resources/css/theme.css` — MUI‑inspired styling (colors, buttons, inputs)
  - `resources/img/logo.svg` — placeholder logo you can replace with your branding

The theme only overrides styles; it relies on Keycloak's default login templates, so it stays compatible with modern Keycloak versions without template maintenance.

## How to use in another project

1. Copy the `gosignals-mui` folder to your Keycloak installation under `themes/`:

   - Keycloak (Quarkus) distribution on a host:
     - Place at: `<keycloak-home>/themes/gosignals-mui`
   - Containerized Keycloak:
     - Mount into the container at `/opt/keycloak/themes/gosignals-mui`

2. Enable the theme in your realm:

   - Open Keycloak Admin Console for your realm
   - Go to: Realm Settings → Themes
   - Set “Login Theme” to `gosignals-mui`
   - Save

3. (Optional) Development tips

   - Disable theme caching while iterating styles:
     - Admin Console → Realm Settings → Themes → Turn off caching, or
     - Start Keycloak with `--spi-theme-static-max-age=-1 --spi-theme-cache-themes=false --spi-theme-cache-templates=false`
   - Replace `resources/img/logo.svg` with your product logo. The CSS scales it appropriately.

## Customizing colors

Edit `resources/css/theme.css` at the top to change the CSS variables. They mirror the app’s MUI tokens:

- `--mui-primary-*` and `--mui-green-*` map to values from `src/theme.ts`
- Update variables to match your brand; the rest of the styles will follow automatically

## Scope and compatibility

- Theme type: `login` (does not modify the Admin Console or Account Console)
- Parent: `keycloak` — only styles are overridden; HTML templates remain Keycloak defaults
- Tested with recent Keycloak versions that ship the Quarkus distribution
