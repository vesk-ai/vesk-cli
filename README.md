# Vesk website

Single-page, static site for vesktechnologies.com. Plain HTML/CSS/JS: no build step, no framework, no server code, no cookies, no analytics. Copy source: VES-27 (approved v2).

```
site/            <- upload the CONTENTS of this folder
  index.html     (must end up at the web root)
  404.html  .htaccess  robots.txt  favicon.svg
  css/style.css  js/main.js  js/config.js
  img/           (optional; the design needs no images)
```

## Preview locally
`cd site && python3 -m http.server 8000`, then open http://localhost:8000.

## Upload by FTP
1. Connect with your FTP/SFTP client to the hosting account.
2. Open the web root folder (often `public_html`, `www` or `htdocs`; check your host's docs).
3. Upload everything **inside** `site/` (not the `site` folder itself) so `index.html` sits directly in the web root.
4. Include the hidden `.htaccess` (enable "show hidden files" in your client). It sets the 404 page, gzip, caching and two safe headers. It works on Apache; on other servers it can be skipped.
5. Visit https://vesktechnologies.com and hard-refresh. Enable HTTPS in the hosting panel if it is not already.

No routing fallback is needed: the page is a single `index.html` with anchor links (`#how`, `#ask`, `#who`, `#early-access`).

## Before launch (open items from the copy brief)
- **Contact email:** set `CONTACT_EMAIL` in `site/js/config.js`. Until then the form sends nothing and says so. When set, submitting opens the visitor's email app pre-filled (no server involved). For a true form backend, the board must pick and approve one.
- **Privacy notice:** the footer has a short placeholder statement; replace with the real notice and link.
- **Entity name** in the footer ("Vesk Technologies"), **availability wording** (see below) and the **founder line**: founder to confirm.
- **Availability claim:** the site has no roadmap section and states one status only ("Pre-launch" in the hero). The module text and the "Ask the record" sample are written in present tense and labelled illustrative. Do not remove the Pre-launch label or the Illustrative notes until the product is live; claiming availability that does not exist is a legal and trust risk the board must own.
- No regulatory claims are included by design until Research supplies sources.

## Editing notes
- All copy is in `site/index.html`. Sample data in the hero slip and "Ask the record" lives in `site/js/main.js` and `index.html`; it is fictional and labelled so.
- Colours are CSS variables at the top of `site/css/style.css`.
