# Vesk website

Single-page, static site for vesktechnologies.com. Plain HTML/CSS/JS: no build step, no framework, no server code, no cookies, no analytics. Copy source: VES-27 (approved v2).

```
site/            <- upload the CONTENTS of this folder
  index.html     (must end up at the web root)
  404.html  .htaccess  robots.txt  favicon.svg
  css/style.css  js/main.js  js/config.js
  img/           (put real images here; see IMAGE_PROMPTS.md)
```

## Preview locally
`cd site && python3 -m http.server 8000`, then open http://localhost:8000.

## Upload by FTP
1. Connect with your FTP/SFTP client to the hosting account.
2. Open the web root folder (often `public_html`, `www` or `htdocs`; check your host's docs).
3. Upload everything **inside** `site/` (not the `site` folder itself) so `index.html` sits directly in the web root.
4. Include the hidden `.htaccess` (enable "show hidden files" in your client). It sets the 404 page, gzip, caching and two safe headers. It works on Apache; on other servers it can be skipped.
5. Visit https://vesktechnologies.com and hard-refresh. Enable HTTPS in the hosting panel if it is not already.

No routing fallback is needed: the page is a single `index.html` with anchor links (`#modules`, `#roadmap`, `#who`, `#early-access`).

## Before launch (open items from the copy brief)
- **Contact email:** set `CONTACT_EMAIL` in `site/js/config.js`. Until then the form sends nothing and says so. When set, submitting opens the visitor's email app pre-filled (no server involved). For a true form backend, the board must pick and approve one.
- **Privacy notice:** the footer has a short placeholder statement; replace with the real notice and link.
- **Entity name** in the footer ("Vesk Technologies"), **per-module status**, **real roadmap items** and the **founder line**: founder to confirm.
- **Images:** see `IMAGE_PROMPTS.md`.
- No regulatory claims are included by design until Research supplies sources.

## Editing notes
- All copy is in `site/index.html`. Everything "not shipped" is labelled Planned / Pre-launch; keep it that way until features ship.
- Colours are CSS variables at the top of `site/css/style.css`.
