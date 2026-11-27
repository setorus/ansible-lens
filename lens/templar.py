"""Jinja2 environment configured like Ansible's, plus lazy variable scope."""
import functools
import posixpath
from collections.abc import Mapping
from itertools import chain, islice

from jinja2 import Undefined, pass_context
from jinja2.exceptions import TemplateError, TemplateSyntaxError
from jinja2 import nodes
from jinja2.nativetypes import NativeCodeGenerator, NativeEnvironment

from . import filters as F
from .values import Runtime, SymUndefined, Unsafe, Vaulted, current, tracing

OMIT = "__omit_place_holder__lens"

# inventory/connection variables: never gathered facts, so unset means undefined
CONNECTION_VARS = {
    "ansible_host", "ansible_port", "ansible_user", "ansible_password", "ansible_connection",
    "ansible_python_interpreter", "ansible_shell_type", "ansible_shell_executable", "ansible_managed",
    "ansible_check_mode", "ansible_diff_mode", "ansible_loop", "ansible_loop_var", "ansible_index_var",
    "ansible_private_key_file", "ansible_timeout", "ansible_pipelining", "ansible_inventory_sources",
}
CONNECTION_PREFIXES = ("ansible_ssh_", "ansible_become", "ansible_winrm_", "ansible_netconf_",
                       "ansible_network_", "ansible_httpapi_", "ansible_paramiko_", "ansible_play_",
                       "ansible_parent_role", "ansible_role_", "ansible_run_tags", "ansible_skip_tags")


def _s(v):
    if v is None:
        return ""
    return v if isinstance(v, str) else str(v)


def concat(values):
    """Ansible-core 2.19 style: a lone expression keeps its native type,
    anything mixed with text becomes a string."""
    head = list(islice(values, 2))
    if not head:
        return ""
    if len(head) == 1:
        v = head[0]
        if isinstance(v, SymUndefined):
            v._use()
        return v
    return "".join(_s(v) for v in chain(head, values))


def is_template(s):
    return isinstance(s, str) and not isinstance(s, Unsafe) and ("{{" in s or "{%" in s or "{#" in s)


def _wrap(name, fn, kind):
    """Make filter/test Runtime-aware: a Runtime input yields a Runtime output."""
    skip = 1 if hasattr(fn, "jinja_pass_arg") else 0

    @functools.wraps(fn)
    def w(*args, **kw):
        if len(args) > skip:
            v = args[skip]
            if isinstance(v, Runtime):
                v._t()
                sep = " | " if kind == "filter" else " is "
                return Runtime(f"{v._p}{sep}{name}")
            if isinstance(v, SymUndefined) and kind == "filter":
                v._use()
        return fn(*args, **kw)
    return w


class _CodeGen(NativeCodeGenerator):
    """No compile-time folding of expressions: folded constants come back as
    their repr() string, which would lose the native type."""

    def _output_child_to_const(self, node, frame, finalize):
        if isinstance(node, nodes.TemplateData):
            return super()._output_child_to_const(node, frame, finalize)
        raise nodes.Impossible()


class Env(NativeEnvironment):
    code_generator_class = _CodeGen
    concat = staticmethod(concat)


class Templar:
    def __init__(self, analyzer):
        self.an = analyzer
        self.env = Env(
            undefined=SymUndefined,
            trim_blocks=True,
            keep_trailing_newline=True,
            extensions=["jinja2.ext.loopcontrols", "jinja2.ext.do"],
        )
        self.env.filters.update(F.FILTERS)
        self.env.tests.update(F.TESTS)
        for k, v in list(self.env.filters.items()):
            if k not in F.PASSTHROUGH:
                self.env.filters[k] = _wrap(k, v, "filter")
        for k, v in list(self.env.tests.items()):
            if k not in F.PASSTHROUGH:
                self.env.tests[k] = _wrap(k, v, "test")
        for k in list(self.env.filters):
            ns = F.FILTER_NAMESPACES.get(k, "ansible.builtin")
            self.env.filters[f"{ns}.{k}"] = self.env.filters[k]
        for k in list(self.env.tests):
            self.env.tests[f"ansible.builtin.{k}"] = self.env.tests[k]
        self.env.globals.update(
            lookup=self._lookup, query=self._query, q=self._query,
            now=lambda utc=False, fmt=None: Runtime("now()"),
            undef=lambda hint=None: SymUndefined(sym=hint or "undef()"),
        )
        self._cache = {}

    # ---------------------------------------------------------------- render
    def compile(self, s):
        t = self._cache.get(s)
        if t is None:
            t = self.env.from_string(s)
            self._cache[s] = t
        return t

    def render_str(self, s, scope, extra=None):
        if not is_template(s):
            return s
        try:
            t = self.compile(s)
        except TemplateSyntaxError as e:
            self._err(f"template syntax error: {e.message} (line {e.lineno})")
            return f"⟨syntax error: {e.message}⟩"
        parent = scope if not extra else _Overlay(scope, extra)
        ctx = t.new_context(parent, shared=True)
        try:
            return concat(t.root_render_func(ctx))
        except RecursionError:
            self._err("recursive template")
            return "⟨error: recursion⟩"
        except Exception as e:  # noqa: BLE001
            msg = getattr(e, "message", None) or str(e) or type(e).__name__
            self._err(f"{type(e).__name__}: {msg}")
            return f"⟨error: {msg}⟩"

    def template(self, value, scope, extra=None):
        if isinstance(value, (Unsafe, Vaulted)):
            return value
        if isinstance(value, str):
            return self.render_str(value, scope, extra)
        if isinstance(value, Mapping) and not isinstance(value, (VarScope, HostVars)):
            return {self.template(k, scope, extra): self.template(v, scope, extra) for k, v in value.items()}
        if isinstance(value, list):
            return [self.template(v, scope, extra) for v in value]
        return value

    def conditional(self, expr, scope, extra=None):
        """Evaluate a ``when``-style expression. Returns (result, trace, warn)."""
        warn = None
        with tracing() as t:
            if isinstance(expr, bool):
                return expr, t, None
            if expr is None:
                return True, t, None
            s = str(expr).strip()
            if s.startswith("{{") and s.endswith("}}") and s.count("{{") == 1:
                warn = "conditional should not include Jinja2 delimiters"
                s = s[2:-2].strip()
            out = self.render_str("{% if " + s + " %}True{% else %}False{% endif %}", scope, extra)
            if t.errors or t.undefined:
                res = "error"
            elif t.runtime:
                res = "unknown"
            else:
                res = out == "True"
        return res, t, warn

    def _err(self, msg):
        t = current()
        if t is not None:
            t.add_error(msg)

    # ---------------------------------------------------------------- lookups
    @pass_context
    def _lookup(self, ctx, name, *terms, **kw):
        wantlist = kw.pop("wantlist", False)
        res = self._run_lookup(ctx, name, terms, kw)
        if isinstance(res, Runtime) or wantlist:
            return res
        if isinstance(res, list):
            return ",".join(_s(x) for x in res) if len(res) != 1 else res[0]
        return res

    @pass_context
    def _query(self, ctx, name, *terms, **kw):
        res = self._run_lookup(ctx, name, terms, kw)
        return res if isinstance(res, (list, Runtime)) else [res]

    def _run_lookup(self, ctx, name, terms, kw):
        name = name.rsplit(".", 1)[-1] if name.startswith(("ansible.builtin.", "community.")) else name
        scope = ctx.parent
        an = self.an
        flat = []
        for t in terms:
            if isinstance(t, list):
                flat += t
            else:
                flat.append(t)
        if name in ("items", "list"):
            return list(flat) if name == "list" else F.f_flatten(flat, 1)
        if name == "dict":
            out = []
            for d in flat:
                out += F.f_dict2items(d)
            return out
        if name == "indexed_items":
            return [[i, x] for i, x in enumerate(flat)]
        if name == "together":
            return F.f_zip_longest(*terms)
        if name in ("nested", "cartesian"):
            return F.f_product(*terms)
        if name == "subelements":
            return F.f_subelements(terms[0], terms[1], **({"skip_missing": True} if len(terms) > 2 else {}))
        if name == "sequence":
            return an.sequence(flat, kw)
        if name == "vars":
            out = []
            for v in flat:
                if v in scope:
                    out.append(scope[v])
                elif "default" in kw:
                    out.append(kw["default"])
                else:
                    raise KeyError(f"No variable found with this name: {v}")
            return out
        if name == "varnames":
            import re  # noqa: PLC0415
            return [k for k in scope if any(re.search(p, k) for p in flat)]
        if name in ("file", "template", "first_found", "fileglob"):
            return an.file_lookup(name, flat, kw, scope)
        if name == "env":
            return Runtime(f"env:{','.join(map(str, flat))}") if len(flat) <= 1 else [Runtime(f"env:{x}") for x in flat]
        return Runtime(f"lookup('{name}', {', '.join(map(repr, flat))})")


class _Overlay(Mapping):
    """Extra template-local vars layered over a scope (template module vars)."""

    def __init__(self, base, extra):
        self.base, self.extra = base, extra

    def __getitem__(self, k):
        if k in self.extra:
            return self.extra[k]
        return self.base[k]

    def __contains__(self, k):
        return k in self.extra or k in self.base

    def __iter__(self):
        return iter(set(self.extra) | set(self.base))

    def __len__(self):
        return len(set(self.extra) | set(self.base))


class VarScope(Mapping):
    """Layered variables, lowest precedence first, templated lazily on access
    (that is how Ansible resolves ``a: "{{ b }}"``)."""

    def __init__(self, templar, layers, facts_runtime=False, globals_=None):
        self.tp = templar
        self.layers = [(n, d) for n, d in layers if d]
        self.facts_runtime = facts_runtime
        self.globals = globals_ if globals_ is not None else templar.env.globals
        self._busy = set()

    def find(self, k):
        for name, d in reversed(self.layers):
            if k in d:
                return name, d[k]
        return None

    def sources(self, k):
        return [name for name, d in self.layers if k in d]

    def _fact(self, k):
        return self.facts_runtime and k not in CONNECTION_VARS and not k.startswith(CONNECTION_PREFIXES) and \
            (k.startswith("ansible_") or k == "facts")

    def __contains__(self, k):
        return self.find(k) is not None or k in self.globals or self._fact(k)

    def __getitem__(self, k):
        hit = self.find(k)
        t = current()
        if hit is None:
            if k in self.globals:
                return self.globals[k]
            if self._fact(k):
                if t is not None:
                    t.add_ref(k, "facts (gathered at runtime)", None)
                return Runtime(k)
            raise KeyError(k)
        src, raw = hit
        ref = t.add_ref(k, src, raw) if t is not None else None
        if k in self._busy:
            if t is not None:
                t.add_error(f"recursive loop detected in template for '{k}'")
            return SymUndefined(sym=k)
        self._busy.add(k)
        if t is not None:
            t.depth += 1
        try:
            val = self.tp.template(raw, self)
        finally:
            self._busy.discard(k)
            if t is not None:
                t.depth -= 1
        if ref is not None:
            ref["value"] = val
        return val

    def keys_all(self):
        seen = []
        for _, d in self.layers:
            for k in d:
                if k not in seen:
                    seen.append(k)
        return seen

    def __iter__(self):
        return iter(self.keys_all())

    def __len__(self):
        return len(self.keys_all())


class HostVars(Mapping):
    def __init__(self, analyzer, current_host, current_scope_fn):
        self.an, self.host, self.cur = analyzer, current_host, current_scope_fn

    def __getitem__(self, h):
        if h == self.host:
            return self.cur()
        if h not in self.an.inv.hosts:
            raise KeyError(h)
        return self.an.host_scope(h)

    def __contains__(self, h):
        return h in self.an.inv.hosts

    def __iter__(self):
        return iter(sorted(self.an.inv.hosts))

    def __len__(self):
        return len(self.an.inv.hosts)


def is_omit(v):
    return isinstance(v, str) and v == OMIT


def strip_omit(v):
    if isinstance(v, Mapping) and not isinstance(v, (VarScope, HostVars)):
        return {k: strip_omit(x) for k, x in v.items() if not is_omit(x)}
    if isinstance(v, list):
        return [strip_omit(x) for x in v if not is_omit(x)]
    return v


__all__ = ["Templar", "VarScope", "HostVars", "OMIT", "is_omit", "strip_omit", "is_template", "posixpath",
           "TemplateError", "Undefined"]
