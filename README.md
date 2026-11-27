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

1. Push this folder to a GitHub repository (branch `main`).
2. *Settings → Pages → Source: GitHub Actions*. The workflow runs the tests and publishes.

Any static host works: it is plain files. Local preview: `python3 -m http.server` and open
http://localhost:8000 (a web server is required, `file://` will not load the worker).

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
index.html, assets/        UI (no build step, no npm)
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
