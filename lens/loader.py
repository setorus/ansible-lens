"""Virtual file system, YAML loading with line numbers, inventory parsing."""
import ast
import fnmatch
import posixpath
import re
import shlex

import yaml

from .values import Unsafe, Vaulted

# --------------------------------------------------------------------------- YAML


class LDict(dict):
    """dict that remembers the YAML line it started on."""
    __slots__ = ("line",)


class _Loader(yaml.SafeLoader):
    pass


def _map(loader, node):
    d = LDict()
    d.line = node.start_mark.line + 1
    yield d
    d.update(loader.construct_mapping(node))


def _unsafe(loader, node):
    return Unsafe(loader.construct_scalar(node))


def _vault(loader, node):
    return Vaulted(loader.construct_scalar(node))


_Loader.add_constructor("tag:yaml.org,2002:map", _map)
_Loader.add_constructor("!unsafe", _unsafe)
_Loader.add_constructor("!vault", _vault)
_Loader.add_constructor("!vault-encrypted", _vault)


def load_yaml(text):
    return yaml.load(text, Loader=_Loader)


def line_of(obj):
    return getattr(obj, "line", None)


# --------------------------------------------------------------------------- VFS


def norm(path):
    p = posixpath.normpath(str(path).replace("\\", "/"))
    while p.startswith("./"):
        p = p[2:]
    return "" if p == "." else p.lstrip("/")


class VFS:
    def __init__(self, files):
        self.files = {norm(k): v for k, v in (files or {}).items()}

    def exists(self, path):
        return norm(path) in self.files

    def read(self, path):
        return self.files[norm(path)]

    def isdir(self, path):
        p = norm(path)
        pre = p + "/" if p else ""
        return any(k.startswith(pre) for k in self.files)

    def find(self, name, dirs):
        """First existing file for ``name`` searched in ``dirs``. Absolute paths
        are matched by suffix, since uploaded trees rarely keep the real root."""
        name = str(name)
        tried = []
        if name.startswith("/"):
            n = norm(name)
            tried.append(n)
            if n in self.files:
                return n, tried
            parts = n.split("/")
            for i in range(1, len(parts)):
                suf = "/".join(parts[i:])
                for k in self.files:
                    if k == suf or k.endswith("/" + suf):
                        return k, tried
            return None, tried
        for d in dirs:
            if d is None:
                continue
            cand = norm(posixpath.join(d, name))
            if cand in tried:
                continue
            tried.append(cand)
            if cand in self.files:
                return cand, tried
        return None, tried

    def find_yaml(self, base_dirs, stem):
        """``stem`` with optional .yml/.yaml/.json extension."""
        for d in base_dirs:
            for ext in ("", ".yml", ".yaml", ".json"):
                p = norm(posixpath.join(d, stem + ext))
                if p in self.files and not self.isdir(p):
                    return p
        return None

    def glob(self, pattern, dirs):
        out = []
        for d in dirs:
            pat = norm(posixpath.join(d, pattern))
            out += [k for k in self.files if fnmatch.fnmatch(k, pat) and k not in out]
            if out:
                break
        return sorted(out)


# --------------------------------------------------------------------------- inventory


def _ini_value(v):
    try:
        return ast.literal_eval(v)
    except Exception:  # noqa: BLE001
        return v


def _kv_tokens(tokens):
    out = {}
    for t in tokens:
        if "=" in t:
            k, v = t.split("=", 1)
            out[k] = _ini_value(v)
    return out


_RANGE = re.compile(r"\[([0-9a-zA-Z]+):([0-9a-zA-Z]+)(?::(\d+))?\]")


def expand_hosts(pattern):
    m = _RANGE.search(pattern)
    if not m:
        return [pattern]
    a, b, step = m.group(1), m.group(2), int(m.group(3) or 1)
    head, tail = pattern[: m.start()], pattern[m.end():]
    if a.isdigit() and b.isdigit():
        width = len(a) if a.startswith("0") else 0
        seq = [str(i).zfill(width) for i in range(int(a), int(b) + 1, step)]
    else:
        seq = [chr(i) for i in range(ord(a), ord(b) + 1, step)]
    out = []
    for s in seq:
        out += expand_hosts(head + s + tail)
    return out


class Inventory:
    def __init__(self):
        self.hosts = {}   # name -> vars
        self.groups = {}  # name -> {"hosts": set, "children": set, "vars": {}}
        self.notes = []
        self._group("all")
        self._group("ungrouped")

    def _group(self, name):
        return self.groups.setdefault(name, {"hosts": set(), "children": set(), "vars": {}})

    def add_host(self, name, group=None, hvars=None):
        self.hosts.setdefault(name, {}).update(hvars or {})
        if group:
            self._group(group)["hosts"].add(name)

    # ---- parsers
    def load_yaml(self, data):
        def walk(gname, body):
            g = self._group(gname)
            if not isinstance(body, dict):
                return
            for h, hv in (body.get("hosts") or {}).items():
                for hn in expand_hosts(str(h)):
                    self.add_host(hn, gname, hv if isinstance(hv, dict) else {})
            g["vars"].update(body.get("vars") or {})
            for c, cb in (body.get("children") or {}).items():
                g["children"].add(c)
                walk(c, cb)

        for top, body in data.items():
            if top != "all":
                self._group("all")["children"].add(top)
            walk(top, body)

    def load_ini(self, text):
        section, kind = "ungrouped", "hosts"
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r"^\[([^\]:]+)(?::(\w+))?\]$", line)
            if m:
                section, kind = m.group(1), (m.group(2) or "hosts")
                self._group(section)
                if section not in ("all",):
                    self._group("all")["children"].add(section)
                continue
            if kind == "hosts":
                toks = shlex.split(line, comments=True)
                if not toks:
                    continue
                for hn in expand_hosts(toks[0]):
                    self.add_host(hn, section, _kv_tokens(toks[1:]))
            elif kind == "vars":
                k, _, v = line.partition("=")
                self._group(section)["vars"][k.strip()] = _ini_value(v.strip())
            elif kind == "children":
                child = line.split()[0]
                self._group(child)
                self._group(section)["children"].add(child)
                self._group("all")["children"].discard(child) if section != "all" else None

    def finish(self):
        # children listed under another group are not direct children of all
        nested = set()
        for g, d in self.groups.items():
            if g != "all":
                nested |= d["children"]
        self.groups["all"]["children"] = {c for c in self.groups["all"]["children"] if c not in nested} | (
            set(self.groups) - nested - {"all"})
        for h in self.hosts:
            self.groups["all"]["hosts"].add(h)
        for h in self.hosts:
            if not [g for g in self.groups_of(h) if g not in ("all", "ungrouped")]:
                self.groups["ungrouped"]["hosts"].add(h)
        self.groups["all"]["children"].discard("all")

    # ---- queries
    def parents(self, group):
        return [g for g, d in self.groups.items() if group in d["children"]]

    def depth(self, group, _seen=None):
        if group == "all":
            return 0
        _seen = (_seen or set()) | {group}
        ps = [p for p in self.parents(group) if p not in _seen]
        return 1 + max((self.depth(p, _seen) for p in ps), default=0)

    def groups_of(self, host):
        direct = {g for g, d in self.groups.items() if host in d["hosts"]}
        out, stack = set(), list(direct)
        while stack:
            g = stack.pop()
            if g in out:
                continue
            out.add(g)
            stack += self.parents(g)
        out.add("all")
        return out

    def sorted_groups_of(self, host):
        return sorted(self.groups_of(host), key=lambda g: (self.depth(g), g))

    def members(self, group):
        out, stack, seen = set(), [group], set()
        while stack:
            g = stack.pop()
            if g in seen or g not in self.groups:
                continue
            seen.add(g)
            out |= self.groups[g]["hosts"]
            stack += list(self.groups[g]["children"])
        return out

    def groups_magic(self):
        return {g: sorted(self.members(g)) for g in sorted(self.groups)}

    # ---- host patterns
    def match(self, pattern):
        if isinstance(pattern, list):
            pattern = ",".join(str(p) for p in pattern)
        terms = [t.strip() for t in re.split(r"[,:](?![^\[]*\])", str(pattern)) if t.strip()]
        result = []
        for t in terms:
            if t.startswith("!"):
                sel = self._term(t[1:])
                result = [h for h in result if h not in sel]
            elif t.startswith("&"):
                sel = self._term(t[1:])
                result = [h for h in result if h in sel]
            else:
                result += [h for h in sorted(self._term(t)) if h not in result]
        return result

    def _term(self, t):
        if t in ("all", "*"):
            return set(self.hosts)
        if t.startswith("~"):
            rx = re.compile(t[1:])
            return {h for h in self.hosts if rx.search(h)} | set().union(
                *[self.members(g) for g in self.groups if rx.search(g)] or [set()])
        out = set()
        for g in self.groups:
            if fnmatch.fnmatchcase(g, t):
                out |= self.members(g)
        out |= {h for h in self.hosts if fnmatch.fnmatchcase(h, t)}
        if not out and t in ("localhost", "127.0.0.1"):
            out.add(t)
        return out


def parse_inventory(text, path=""):
    inv = Inventory()
    if text is None:
        inv.add_host("localhost")
        inv.notes.append("No inventory selected: implicit localhost only.")
        inv.finish()
        return inv
    data = None
    if not path.endswith((".ini", ".cfg")) and not re.search(r"^\s*\[", text, re.M):
        try:
            data = load_yaml(text)
        except yaml.YAMLError:
            data = None
    if isinstance(data, dict):
        inv.load_yaml(data)
    else:
        inv.load_ini(text)
    inv.finish()
    if not inv.hosts:
        inv.add_host("localhost")
        inv.notes.append("Inventory has no hosts: implicit localhost added.")
        inv.finish()
    return inv


_GV = re.compile(r"(?:^|/)(group_vars|host_vars)/([^/]+?)(?:\.(?:ya?ml|json))?$")
_GVD = re.compile(r"(?:^|/)(group_vars|host_vars)/([^/]+)/[^/]+\.(?:ya?ml|json)$")


def collect_var_files(vfs):
    """{'group_vars': {group: [paths]}, 'host_vars': {host: [paths]}}"""
    out = {"group_vars": {}, "host_vars": {}}
    for p in sorted(vfs.files):
        m = _GVD.search(p) or _GV.search(p)
        if m:
            out[m.group(1)].setdefault(m.group(2), []).append(p)
    return out
