---
layout: default
title: Guide
permalink: /docs/
---

[Open the checker]({{ '/' | relative_url }})

## What it does

Ansible Lens reads a playbook and the project around it, picks one inventory host, and shows what
Ansible *would* pass to each module. It never runs a playbook, never connects to a host, and never
looks inside a module.

For every task you get:

- the module, normalised to its full name (`copy` becomes `ansible.builtin.copy`);
- each argument after templating, `omit` removal, `k=v` and free-form parsing and `args:` merging;
- the variables behind each value and the layer each one came from;
- the result of each `when`: true, false, unknown at runtime, or error;
- loop items, block/rescue/always, imported and included tasks and roles, handlers;
- the rendered output of `template` tasks.

## Quick start

1. **Open folder** or drop a project folder on the page. Files stay in your browser.
2. Pick the playbook, the inventory (INI or YAML) and the host.
3. Put `-e` values in **Extra vars**. Put stand-in facts in **Mock facts**, for example
   `os_family: Debian` (the `ansible_` prefix is optional).
   Put controller environment variables in **Environment**, one `KEY=value` per line (a `.env`
   file pastes as is) or as a YAML mapping. `lookup('env', ...)` returns these values. Names you
   leave out stay `⟨runtime:env:NAME⟩`.
4. Open a task to see its arguments. Click `file:line` to jump to the source.

Drag the bar between the editor and the analysis to resize them. Arrow keys also move the bar when
it has focus (Shift moves it in larger steps), and a double-click resets it. **Expand** gives one
side the full width. **Restore** brings the other side back. The browser remembers the layout.

**Share link** packs every file into the part of the URL after `#`. Browsers do not send that part
to the server.

## Reading the results

| Mark | Meaning |
|---|---|
| runs | conditions are true for this host |
| depends on runtime | the outcome needs a value only known while the play runs |
| skipped | a condition is false, or a handler is never notified |
| error | Ansible would fail here: undefined variable, bad loop data, syntax error |
| `⟨runtime:…⟩` | value derived from a registered result, a gathered fact, `lookup('env')` for a name not in **Environment**, `now()` |
| `⟨undefined:…⟩` | variable used without a definition or default |
| omit | argument removed by `omit`; the module never receives it |

{% raw %}
Values are templated lazily, as Ansible does: `a: "{{ b }}"` is resolved when `a` is used. A lone
`{{ expr }}` keeps its type (int, list, dict), like ansible-core 2.19.
{% endraw %}

## Variable precedence

Lowest first: role defaults, inventory group vars, `group_vars/` files, inventory host vars,
`host_vars/` files, facts, play vars, vars_prompt, vars_files, role vars, block vars, task vars,
include_vars, set_fact and register, role and include params, loop vars, magic vars, extra vars.

The **Variables** tab shows the winning layer for every variable and strikes through the layers it
overrode.

## Limits

- `changed_when`, `failed_when` and `until` are shown but not evaluated: they need the module result.
- Notified handlers are marked *depends on runtime*, since they fire only when a task reports a change.
- `add_host`, `group_by`, `meta: end_*`, `serial` and strategies are noted, not simulated.
- `!vault` values stay encrypted placeholders.
- Collection filters other than common ones (`json_query`, `ipaddr`) show as runtime values.
