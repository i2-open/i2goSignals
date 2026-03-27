### Bug report: Keycloak 26.4.5 theme issues (duplicate header, logo placement) — gosignals-mui

Reported by: Junie automation on behalf of project maintainers
Date: 2025-12-11 16:09 local

Summary
- We are unable to reliably customize the Keycloak login page using the custom theme `gosignals-mui` on Keycloak 26.4.5 (Quarkus). Despite multiple iterations, the login page shows an extra header area to the right of the form, and placement of realm display name and logo is inconsistent.
- We need Junie team support to diagnose Keycloak 26 + PatternFly v5 template/DOM structure interactions and advise the correct minimal overrides.
- IMPORTANT NOTE: During this session, Junie kept going back and forth without making progress. It became trapped in a loop wasting a lot of time. Junie seems unable to report that it is not able to do certain things.

Environment
- OS: macOS (developer machine), Docker Desktop
- Keycloak: quay.io/keycloak/keycloak:26.4.5 (Quarkus 3.27)
- Database: Postgres (alpine)
- Compose file: docker-compose-dev.yml
- Theme mount: `./config/keycloak/themes:/opt/keycloak/themes`
- Realm import: `./config/keycloak/realm:/opt/keycloak/data/import`, realm `gosignals`
- Theme caching disabled and theme DEBUG enabled:
  - `--spi-theme-static-max-age=-1`
  - `--spi-theme-cache-themes=false`
  - `--spi-theme-cache-templates=false`
  - `--log-level=org.keycloak.theme:DEBUG`

Theme structure (current)
```
config/keycloak/themes/gosignals-mui/
├─ theme.properties                # parent=keycloak.v2, types=login, styles=css/theme.css
└─ login/
   ├─ login.ftl                    # overrides to control header/title content
   └─ resources/
      ├─ css/theme.css             # styling, attempts to hide duplicate header and center logo
      └─ img/logo.svg
```

Key files (excerpts)
- theme.properties
```
parent=keycloak.v2
types=login
styles=css/theme.css
locales=en
displayName=GoSignals MUI
```

- login.ftl (sections)
```
<#if section = "header">
  <!-- intentionally blank -->
<#elseif section = "title">
  <div id="kc-realm-name">${realm.displayNameHtml?has_content?then(realm.displayNameHtml?no_esc, realm.displayName!realm.name)}</div>
  <div id="kc-logo-above" style="width:128px;height:128px;margin:12px auto; background:url('${url.resourcesPath}/img/logo.svg') no-repeat center/contain; display:block;"></div>
<#elseif section = "form">
  ...
```

- theme.css (relevant intent)
  - Center realm name and logo
  - Hide the duplicate in-form header only
  - Hide outer PF v5/v4 container header if necessary

Observed behavior (actual)
- On the login page, an extra header appears to the right of the form. DOM snippet from browser DevTools:
```
<div class="pf-v5-c-login">
  <div class="pf-v5-c-login__container">
    <header id="kc-header" class="pf-v5-c-login__header">
      <div id="kc-header-wrapper" class="pf-v5-c-brand">GoSignals Realm</div>
    </header>
    <main class="pf-v5-c-login__main">
      <div class="pf-v5-c-login__main-header">
        <h1 id="kc-page-title"> ... custom realm name + logo ... </h1>
      </div>
      ...
```
- Even after attempts to hide only the outer container header, the `<header id="kc-header" class="pf-v5-c-login__header">` remains rendered and visible to the right of the form.
- The realm display name and logo inserted into the title section render correctly, centered above the form, but the extra header remains visible.

Expected behavior
- Only one header/title should appear: realm display name centered above the logo, and the logo above the input fields, within the main content column. No extra header should appear to the right.

Steps to reproduce
1) From repo root, start Keycloak with dev compose:
   - `docker compose -f docker-compose-dev.yml down`
   - `docker compose -f docker-compose-dev.yml up -d keycloak`
2) Open Admin Console → Realm: `gosignals` → Realm Settings → Themes → select `gosignals-mui` as Login Theme if not already.
3) Open the login page for realm `gosignals` in a private window and hard refresh.
4) Observe the duplicate header: right of the form appears a `<header id="kc-header" class="pf-v5-c-login__header">` containing the realm name, while the main title area also shows the custom realm name + logo.

Evidence
- DOM (full snippet provided by user) shows both:
  - Outer container header: `header#kc-header.pf-v5-c-login__header`
  - Main header: `div.pf-v5-c-login__main-header > h1#kc-page-title` (contains our custom content)
- Logs: Theme loaded; no current error about missing templates. Earlier in the session, a “Failed to find LOGIN theme ... using built-in themes” occurred, addressed by mounting entire `/opt/keycloak/themes` and adopting the `login/` structure.

Attempts made (chronological highlights)
1) Volume mount fixes: corrected path typo; then mounted entire `./config/keycloak/themes:/opt/keycloak/themes`.
2) Disabled theme caches, enabled DEBUG logs for theme: startup flags as listed above.
3) Updated theme to Keycloak 26+ structure: moved assets under `gosignals-mui/login/resources/**`.
4) Switched parent to `keycloak.v2` (recommended for KC 26).
5) CSS-only approach: attempted to hide duplicate header/title using selectors scoped to PF v5/v4 containers and legacy `.card-pf`.
6) Template adjustments: rendered realm name + logo in the `title` section; left `header` section blank; also tried blanking the `title` section to remove parent title when needed.
7) Multiple iterations trying to target only the outer container header without impacting the main title content.

Current status
- Theme is discovered and selectable; assets load.
- The duplicate outer header `header#kc-header.pf-v5-c-login__header` still appears in the layout, positioned to the right of the form, despite CSS selectors intended to hide it. The top/left custom header content is correct.

Hypotheses / questions for Junie team
1) In Keycloak 26 PF v5, is `header#kc-header` rendered by a fragment that ignores theme CSS from `login/resources/css/theme.css` due to a different resource pipeline or selector scope? Do we need to override another template section (e.g., `header`) or specific fragment to prevent the outer header from rendering at all?
2) Is there a change to section mapping in `registrationLayout` requiring content in the `header` section to suppress the outer container header, rather than leaving it blank? The current approach leaves `header` empty and renders in `title`.
3) Should the theme override a specific template (e.g., copy `base/login/login.ftl` from `keycloak.v2` and remove the outer header DOM block) for KC 26 instead of CSS‑only suppression?
4) Are there known PF v5 layout changes that require using `:has()` selectors or additional containment to reliably target `pf-v5-c-login__header`?

What we need
- Guidance on the recommended minimal override to remove/hide the outer PF v5 container header (`header#kc-header.pf-v5-c-login__header`) in Keycloak 26 while keeping custom content in the main title area.
- Confirmation whether the best practice is:
  - CSS‑only (provide exact selectors known to work in KC 26), or
  - Template override (which file/section to override cleanly to avoid maintenance burden).

How to collect more data (if needed)
- Increase log verbosity further: `--log-level=org.keycloak.theme:TRACE`.
- Inspect resolved templates by enabling template caching debug or printing resolved theme chain.
- Share screenshots and HAR if required (not attached here due to repo size constraints).

Contacts / Maintainers
- Project: i2goSignals
- Theme path in repo: `config/keycloak/themes/gosignals-mui`
- Compose file: `docker-compose-dev.yml`

Thank you for assisting with a targeted recommendation for KC 26 + PF v5.
