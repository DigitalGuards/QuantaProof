# QuantaStark website

The public site at `https://quantastark.com`: a static, single-page research note with SEO value while there is no public QRL 2.0 testnet to deploy against. It presents the measured numbers, the proof flow, a disabled preview of the `StateBridge` interface and the research status. Plain HTML and CSS; no JavaScript, no build step, no external scripts. The only external requests are the Google Fonts stylesheet and its font files, and the page degrades to the system font stack without them.

## Layout

| Path                                                          | Role                                                                                         |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `index.html`                                                  | The page. Relative asset paths, so it also renders from `file://`.                           |
| `404.html`                                                    | Error page (root-relative paths; serve it with `error_page 404 /404.html` or the equivalent) |
| `assets/css/site.css`                                         | Stylesheet: the report layout, the page grid and the bridge-preview form styles              |
| `img/og-image.png`                                            | 1200x630 social card; the path is the family convention, keep it                             |
| `favicon.svg`, `favicon.png`, `apple-touch-icon.png`          | Icons (the PNGs are generated)                                                               |
| `robots.txt`, `sitemap.xml`, `humans.txt`, `site.webmanifest` | Crawler and manifest files                                                                   |
| `tools/og-image.py`                                           | Generates the social card and the PNG icons                                                  |

Everything under `assets/` is meant to be served with long cache headers; every other path stays uncached. Bump the `?v=` query string on the `<link>` tag in `index.html` and `404.html` when a file under `assets/` changes.

## Design

The page is set like a technical report. One text column with a measure of about 70 characters carries the prose; the masthead, the section rules, the wide tables and the footer share a wider frame, and the section numbers hang in the margin on wide viewports. One accent colour (the ember of the DigitalGuards family) marks links, section numbers and the two headline gas figures; identifiers and numbers are monospace. The fonts are the family's (Sora for headings, Instrument Sans for text, JetBrains Mono for data). The bridge preview is a real form inside a disabled `fieldset`, with the network status as plain text.

Copy rules: exact numbers from `docs/GAS-REPORT.md`, `docs/BRIDGE.md` and the README; no em dashes; none of the contrastive-negation shapes `scripts/lint-prose.js` warns about; no filler words.

## Deploy

`scripts/deploy-site.sh` (repository root) tars `site/` without `README.md` and `tools/`, ships it over SSH, extracts it next to the webroot, sets the web server's ownership (`www-data:www-data` unless `QUANTASTARK_OWNER` says otherwise) and swaps it into place: the previous webroot is renamed to `<webroot>.previous-<timestamp>` and the new tree moved in. Every host detail comes from the environment:

| Variable                    | Required | Meaning                                                                |
| --------------------------- | -------- | ---------------------------------------------------------------------- |
| `QUANTASTARK_DEPLOY_HOST`   | yes      | SSH host                                                               |
| `QUANTASTARK_DEPLOY_USER`   | yes      | SSH user                                                               |
| `QUANTASTARK_WEBROOT`       | no       | Target directory on the host (default `/var/www/quantastark`)          |
| `QUANTASTARK_DEPLOY_SUDO`   | no       | `1` prefixes the remote commands with `sudo` (needs passwordless sudo) |
| `QUANTASTARK_OWNER`         | no       | Owner of the deployed tree (default `www-data:www-data`)               |
| `QUANTASTARK_SSH_OPTS`      | no       | Extra `ssh` options, for example `-p 2222`                             |
| `QUANTASTARK_KEEP_PREVIOUS` | no       | How many `.previous-*` copies to keep (default 3)                      |

```bash
QUANTASTARK_DEPLOY_HOST=example.invalid QUANTASTARK_DEPLOY_USER=deploy QUANTASTARK_DEPLOY_SUDO=1 \
  ./scripts/deploy-site.sh
```

Without sudo the SSH user has to be able to `chown` to the owner, which in practice means root. The script prints the webroot listing and the name of the previous copy; rolling back is one `mv` of that copy.

## Social card and icons

```bash
python3 site/tools/og-image.py            # writes img/og-image.png, favicon.png, apple-touch-icon.png
python3 site/tools/og-image.py --fonts /path/to/ibm-plex
```

Needs Pillow and NumPy plus the IBM Plex Sans (variable or static Bold and Regular) and IBM Plex Mono Medium files; the tool searches `--fonts`, `QUANTASTARK_FONT_DIR`, then the usual user and system font directories. The card is the family layout: dark gradient, the mark, the wordmark, one tagline line, the domain and the ember bar. The mark geometry is the one in `favicon.svg`.

## Checks

From the repository root: `npm run format:check` (Prettier covers the HTML, CSS, JSON and Markdown here) and `npm run lint:prose`. Open `site/index.html` from disk to check the page renders without a server. Check both widths (1280 and 390 pixels) after a layout change: the wide table scrolls horizontally on narrow screens and everything else reflows.
