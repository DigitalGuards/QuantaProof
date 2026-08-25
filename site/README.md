# QuantaStark website

The public site at `https://quantastark.com`: a static, single-page placeholder with SEO value while there is no public QRL 2.0 testnet to deploy against. It presents the measured numbers, the proof flow, a disabled preview of the `StateBridge` interface and the research status. Plain HTML, CSS and a few lines of vanilla JavaScript; no build step, no external scripts.

## Layout

| Path                                                          | Role                                                                                         |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `index.html`                                                  | The page. Relative asset paths, so it also renders from `file://`.                           |
| `404.html`                                                    | Error page (root-relative paths; serve it with `error_page 404 /404.html` or the equivalent) |
| `assets/css/site.css`                                         | Stylesheet ("Obsidian & Ember" tokens shared with the other DigitalGuards sites)             |
| `assets/js/site.js`                                           | The bridge preview's "not connected" hint                                                    |
| `img/og-image.png`                                            | 1200x630 social card; the path is the family convention, keep it                             |
| `favicon.svg`, `favicon.png`, `apple-touch-icon.png`          | Icons (the PNGs are generated)                                                               |
| `robots.txt`, `sitemap.xml`, `humans.txt`, `site.webmanifest` | Crawler and manifest files                                                                   |
| `tools/og-image.py`                                           | Generates the social card and the PNG icons                                                  |

Everything under `assets/` is meant to be served with long cache headers; every other path stays uncached. Bump the `?v=` query string on the `<link>` and `<script>` tags in `index.html` and `404.html` when a file under `assets/` changes.

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

Needs Pillow and NumPy plus the IBM Plex Sans (variable or static Bold and Regular) and IBM Plex Mono Medium files; the tool searches `--fonts`, `QUANTASTARK_FONT_DIR`, then the usual user and system font directories. The mark geometry is the one in `favicon.svg`.

## Checks

From the repository root: `npm run format:check` (Prettier covers the HTML, CSS, JS, JSON and Markdown here) and `npm run lint:prose`. Open `site/index.html` from disk to check the page renders without a server; the Google Fonts link degrades to the system stack offline.
