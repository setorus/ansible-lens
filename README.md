# Ansible Lens

Static Ansible playbook checker that runs entirely in the browser (GitHub Pages friendly).
It **never executes** a playbook or a module. It shows:

- how every Jinja2 expression evaluates for a chosen inventory host, with the variable
  chain behind it (`listen_port ← play vars`, `http_port ← group_vars/ files`, …);
- which module each task calls (normalised to FQCN) and the exact arguments it would receive,
  after templating, `omit` removal, `k=v` / free-form parsing and `args:` merging;
- `when` results (true / false / unknown at runtime / error), loop items, block/rescue/always,
  include/import of tasks and roles, role defaults/vars/meta dependencies, handlers and notify;
- `template` module output rendered from the project's `.j2` files;
- undefined variables, recursive templates, syntax errors, missing files.

Real **Jinja2 3.1** and **PyYAML** run in [Pyodide](https://pyodide.org) inside a Web Worker.
Ansible filters/tests/lookups used in playbooks are re-implemented in `lens/filters.py`.

## Deploy

The site builds with Jekyll and the theme set in `_config.yml` (`jekyll-theme-cayman` by default;
see [adding a theme](https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/adding-a-theme-to-your-github-pages-site-using-jekyll)).
The theme styles `docs.md` (guide at `/docs/`) and `404.md`. The checker itself has no front matter,
so Jekyll copies it unchanged.

Pick one publishing source in *Settings → Pages*:

- **GitHub Actions** (recommended): `.github/workflows/pages.yml` runs the tests, builds with
  `actions/jekyll-build-pages` (same gems as Pages), checks the analyzer files survived the build,
  then deploys.
- **Deploy from a branch**: Pages runs Jekyll itself on `main` / root. The workflow's deploy job
  then fails; delete it or keep only the `test` job.

Change theme: edit `theme:` in `_config.yml`, or switch to `remote_theme:` (instructions inside).

Local preview with Jekyll: `bundle install && bundle exec jekyll serve` (http://localhost:4000).
Without Ruby: `python3 -m http.server` works for the checker; the guide page needs Jekyll.
A web server is required either way: `file://` will not load the worker.

Jekyll pitfalls already handled in `_config.yml`:

- `lens/__init__.py` starts with `_`, which Jekyll drops by default: it is in `include:`.
- `example/` (playbooks full of `{{ }}`) and `tests/` are excluded; the UI uses `example.json`.
- Any new page with front matter that shows Jinja2 code must wrap it in `{% raw %}…{% endraw %}`,
  or Liquid will try to render it.

## Releases

[semantic-release](https://semantic-release.gitbook.io) runs on every push to `main`
(`.github/workflows/release.yml`, after the tests). Version comes from
[Conventional Commits](https://www.conventionalcommits.org):

| Commit | Release |
|---|---|
| `fix:`, `perf:`, `refactor(lens):` | patch |
| `feat:` | minor |
| `feat!:` or a `BREAKING CHANGE:` footer | major |
| `ci:`, `docs:`, `chore:`, `test:`, `style:`, `build:` | none |

On release it:

1. writes the version into `assets/app.js` (`VERSION`, which also cache-busts the worker,
   `lens/*.py` and `example.json`), the `?v=` queries in `index.html` and `lens/__init__.py`
   (`scripts/set-version.mjs`);
2. updates `CHANGELOG.md` and commits all of it as `chore(release): X.Y.Z` to `main`;
   Pages rebuilds from that commit, so the live site shows the new version;
3. tags `vX.Y.Z` and publishes a GitHub Release with notes and `ansible-lens-X.Y.Z.zip`
   (deployable static files).

PRs get a `commitlint` check so every commit that lands on `main` is analysable.
Merge commits and squash merges both work; with squash, the PR title is the commit message.

**Protected `main`:** the default `GITHUB_TOKEN` cannot push the release commit past branch
protection. Create a fine-grained PAT (this repo, *Contents: read and write*), allow its owner
to bypass the rule, and store it as the `RELEASE_TOKEN` secret. Without the secret the
workflow uses `GITHUB_TOKEN`.

Local dry run (Node 26+): `npm ci && GITHUB_TOKEN=… npm run release:dry`.

## Use

- **Open folder** / drag-and-drop a project, or edit files in place. Nothing leaves the browser.
- Pick playbook, inventory (INI or YAML) and host. `group_vars/` and `host_vars/` found anywhere in
  the tree are applied.
- **Extra vars** = `-e`. **Mock facts** replace gathered facts (`os_family: Debian`).
- **Share link** packs all files (deflate + base64url) into the URL fragment; the fragment is never
  sent to a server.

## Model and limits

| Thing | How it is treated |
|---|---|
| Registered results, gathered facts, `lookup('env')`, `now()`, `password_hash`, file tests | symbolic **runtime** value; anything derived from it is marked `⟨runtime:…⟩`, conditions become *unknown* |
| Variable precedence | role defaults < inventory group vars < `group_vars/` < inventory host vars < `host_vars/` < facts < play vars < vars_prompt < vars_files < role vars < block vars < task vars < include_vars < set_fact/register < role/include params < loop vars < magic < extra vars |
| Templating | lazy and recursive like Ansible; a single `{{ expr }}` keeps its native type (ansible-core 2.19 behaviour) |
| `changed_when`, `failed_when`, `until` | shown, not evaluated (need module result) |
| Handlers | notified handlers are *depends on runtime* (they fire only on `changed`) |
| `add_host`, `group_by`, `meta: end_*`, strategies, `serial` | noted, not simulated |
| Collection modules | arguments shown; module internals are never inspected |
| Vault | `!vault` values stay encrypted placeholders |

## Layout

```
index.html, assets/        UI (no build step, no npm; copied as-is by Jekyll)
_config.yml, Gemfile       Jekyll + theme config, local preview
docs.md, 404.md            themed pages
package.json, .releaserc.json, commitlint.config.mjs, scripts/set-version.mjs   release tooling
assets/worker.js           loads Pyodide 0.29.5 + jinja2 + pyyaml, runs lens/
lens/values.py             Runtime / SymUndefined symbolic values, tracing
lens/templar.py            Jinja2 env (native types, trim_blocks), lazy VarScope, lookups
lens/filters.py            Ansible filters and tests
lens/loader.py             YAML with line numbers, virtual FS, inventory (INI/YAML, ranges, patterns)
lens/walker.py             play/role/block/task walker, module + args resolution
example.json               demo project
tests/test_lens.py         pytest suite (CPython; same code runs in Pyodide)
```

Analyzer in CPython: `python3 -c "import lens, json; print(lens.analyze_json(open('example.json').read()))"`.
