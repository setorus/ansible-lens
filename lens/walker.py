"""Static walk over a playbook. Builds a JSON-friendly report; never executes."""
import posixpath
import re
from collections.abc import Mapping

from jinja2 import Undefined

from .filters import to_bool
from .loader import VFS, LDict, collect_var_files, line_of, load_yaml, parse_inventory
from .templar import OMIT, HostVars, Templar, VarScope, is_omit, strip_omit
from .values import Runtime, SymUndefined, Unsafe, Vaulted, tracing

MAX_ITEMS = 50          # loop iterations rendered per task
MAX_INCLUDE_LOOP = 5    # loop iterations expanded for include_* / roles
MAX_DEPTH = 30          # include nesting guard

TASK_KW = {
    "action", "any_errors_fatal", "args", "async", "become", "become_exe", "become_flags", "become_method",
    "become_user", "changed_when", "check_mode", "collections", "connection", "debugger", "delay",
    "delegate_facts", "delegate_to", "diff", "environment", "failed_when", "ignore_errors",
    "ignore_unreachable", "local_action", "loop", "loop_control", "module_defaults", "name", "no_log",
    "notify", "poll", "port", "register", "remote_user", "retries", "run_once", "tags", "throttle",
    "timeout", "until", "vars", "when", "listen",
}
BLOCK_KW = {"block", "rescue", "always"}
SHOW_KW = ["delegate_to", "become", "become_user", "become_method", "run_once", "ignore_errors", "no_log",
           "check_mode", "diff", "environment", "remote_user", "connection", "throttle", "timeout",
           "async", "poll", "retries", "delay", "tags", "delegate_facts"]
AFTER_RUN_KW = ["changed_when", "failed_when", "until"]

BUILTIN = set("""add_host apt apt_key apt_repository assemble assert async_status blockinfile command copy cron
deb822_repository debconf debug dnf dnf5 dpkg_selections expect fail fetch file find gather_facts get_url
getent git group group_by hostname import_playbook import_role import_tasks include_role include_tasks
include_vars iptables known_hosts lineinfile meta mount_facts package package_facts pause ping pip raw
reboot replace rpm_key script service service_facts set_fact set_stats setup shell slurp stat subversion
systemd systemd_service sysvinit tempfile template unarchive uri user validate_argument_spec wait_for
wait_for_connection yum_repository""".split())
FREE_FORM = {"command", "shell", "raw", "script", "win_command", "win_shell", "include_tasks",
             "import_tasks", "include_vars", "meta", "import_playbook"}
FREE_FORM_KEYS = {"chdir", "creates", "removes", "executable", "warn", "stdin", "stdin_add_newline",
                  "strip_empty_ends", "argv", "expand_argument_vars", "cmd", "file", "name", "dir"}
STATUS_ORDER = {"run": 0, "conditional": 1, "error": 2, "skipped": 3}


def worst(a, b):
    return a if STATUS_ORDER.get(a, 0) >= STATUS_ORDER.get(b, 0) else b


# --------------------------------------------------------------------------- JSON


def J(v, depth=0):
    if depth > 12:
        return "…"
    if isinstance(v, Runtime):
        return {"$rt": v._p}
    if isinstance(v, Undefined):
        return {"$undef": getattr(v, "_sym", "?")}
    if isinstance(v, (VarScope, HostVars)):
        return {"$obj": "hostvars / scope"}
    if isinstance(v, Vaulted):
        return {"$obj": "!vault (encrypted, not decrypted)"}
    if isinstance(v, Mapping):
        items = list(v.items())
        out = {str(k): J(x, depth + 1) for k, x in items[:300]}
        if len(items) > 300:
            out["…"] = f"{len(items) - 300} more keys"
        return out
    if isinstance(v, (list, tuple, set, frozenset)):
        seq = list(v)
        out = [J(x, depth + 1) for x in seq[:300]]
        if len(seq) > 300:
            out.append(f"… {len(seq) - 300} more")
        return out
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, str):
        if v == OMIT:
            return {"$omit": True}
        return str(v) if len(v) < 20000 else v[:20000] + "…"
    if v is None or isinstance(v, (bool, int, float)):
        return v
    return {"$obj": repr(v)}


def refs_json(t):
    seen, out = set(), []
    for r in t.refs:
        key = (r["name"], r["depth"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": r["name"], "source": r["source"], "depth": r["depth"],
                    "raw": J(r.get("raw")), "value": J(r.get("value"))})
    return out


def trace_json(t):
    return {"refs": refs_json(t), "undefined": list(t.undefined), "runtime": list(t.runtime),
            "errors": list(t.errors)}


# --------------------------------------------------------------------------- args


def split_args(s):
    """Split k=v / free-form strings on spaces outside quotes and Jinja2 blocks."""
    out, cur, quote, depth, i = [], "", None, 0, 0
    while i < len(s):
        c, two = s[i], s[i:i + 2]
        if quote:
            cur += c
            if c == "\\" and i + 1 < len(s):
                cur += s[i + 1]
                i += 1
            elif c == quote:
                quote = None
        elif two in ("{{", "{%", "{#"):
            depth += 1
            cur += two
            i += 1
        elif two in ("}}", "%}", "#}") and depth:
            depth -= 1
            cur += two
            i += 1
        elif c in "\"'" and not depth:
            quote = c
            cur += c
        elif c.isspace() and not depth:
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur:
        out.append(cur)
    return out


def _unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def parse_kv(s, free_form):
    args, raw, notes = {}, [], []
    for tok in split_args(str(s)):
        m = re.match(r"^([A-Za-z_][\w]*)=(.*)$", tok, re.S)
        if m and (not free_form or m.group(1) in FREE_FORM_KEYS):
            args[m.group(1)] = _unquote(m.group(2))
        else:
            raw.append(tok)
    if raw:
        if free_form:
            args["_raw_params"] = " ".join(raw)
        else:
            notes.append(f"extra free-form params ignored by non free-form module: {' '.join(raw)!r}")
            args["_raw_params"] = " ".join(raw)
    return args, notes


def fqcn(name):
    n = str(name)
    if n.startswith(("ansible.builtin.", "ansible.legacy.")):
        short = n.split(".")[-1]
        return n if n.startswith("ansible.builtin.") else f"ansible.builtin.{short}", short, "builtin"
    if n in BUILTIN:
        return f"ansible.builtin.{n}", n, "builtin"
    if n.count(".") >= 2:
        return n, n.split(".")[-1], "collection"
    return n, n, "unknown"


# --------------------------------------------------------------------------- frames


class Role:
    def __init__(self, name, path):
        self.name, self.path = name, path
        self.defaults, self.vars = {}, {}


class Frame:
    def __init__(self, **kw):
        self.file = kw.get("file")
        self.role = kw.get("role")
        self.block_vars = kw.get("block_vars", {})
        self.params = kw.get("params", {})
        self.loopvars = kw.get("loopvars", {})
        self.whens = kw.get("whens", [])       # inherited (expr, origin)
        self.cap = kw.get("cap", "run")         # worst status the parent allows
        self.cap_note = kw.get("cap_note")
        self.depth = kw.get("depth", 0)
        self.parent_roles = kw.get("parent_roles", [])
        self.handler = kw.get("handler", False)

    def child(self, **kw):
        d = dict(self.__dict__)
        d.update(kw)
        return Frame(**d)

    @property
    def dir(self):
        return posixpath.dirname(self.file) if self.file else ""


class Play:
    def __init__(self, name, pbdir):
        self.name, self.pbdir = name, pbdir
        self.vars, self.prompt, self.vars_files = {}, {}, {}
        self.role_defaults, self.role_vars = {}, {}
        self.handlers = []              # (task, frame)
        self.notified = {}              # name -> "yes" | "maybe"
        self.roles_seen = set()
        self.role_names = []
        self.gather = True
        self.hosts = []
        self.collections = []


# --------------------------------------------------------------------------- analyzer


class Analyzer:
    def __init__(self, inp):
        self.vfs = VFS(inp.get("files") or {})
        self.entry = inp.get("entry")
        self.inv_path = inp.get("inventory") or None
        self.diag = []
        self.ids = 0
        self.tp = Templar(self)
        self.extra = self._parse_vars(inp.get("extra_vars"), "extra vars")
        self.mock_facts = self._parse_vars(inp.get("facts"), "mock facts")
        self.env_vars = self._parse_env(inp.get("env"))
        inv_text = self.vfs.read(self.inv_path) if self.inv_path and self.vfs.exists(self.inv_path) else None
        if self.inv_path and inv_text is None:
            self.warn(f"inventory file not found: {self.inv_path}")
        try:
            self.inv = parse_inventory(inv_text, self.inv_path or "")
        except Exception as e:  # noqa: BLE001
            self.error(f"inventory parse error: {e}")
            self.inv = parse_inventory(None)
        for n in self.inv.notes:
            self.info(n)
        self.host = inp.get("host") or sorted(self.inv.hosts)[0]
        if self.host not in self.inv.hosts:
            self.inv.add_host(self.host)
            self.inv.finish()
            self.warn(f"host '{self.host}' not in inventory, analysed as implicit host")
        self.varfiles = collect_var_files(self.vfs)
        self.host_include_vars = {}
        self.host_facts = {}            # set_fact + register, persists across plays
        self._hs_cache = {}

    # ---------------------------------------------------------- diagnostics
    def _d(self, level, msg, where=None, node=None):
        self.diag.append({"level": level, "msg": msg, "where": where, "node": node})

    def error(self, msg, where=None, node=None):
        self._d("error", msg, where, node)

    def warn(self, msg, where=None, node=None):
        self._d("warn", msg, where, node)

    def info(self, msg, where=None, node=None):
        self._d("info", msg, where, node)

    def _parse_vars(self, text, label):
        if not text or not str(text).strip():
            return {}
        try:
            data = load_yaml(text)
        except Exception as e:  # noqa: BLE001
            self.error(f"{label}: YAML error: {e}")
            return {}
        if isinstance(data, str) and "=" in data:
            return parse_kv(data, False)[0]
        if not isinstance(data, dict):
            self.error(f"{label}: expected a mapping")
            return {}
        return data

    def _parse_env(self, text):
        """Controller environment for lookup('env'): dotenv lines (KEY=value) or a YAML mapping."""
        if not text or not str(text).strip():
            return {}
        lines = [ln.strip() for ln in str(text).splitlines()]
        lines = [ln for ln in lines if ln and not ln.startswith("#")]
        env = {}
        if all(re.match(r"(export\s+)?[A-Za-z_][A-Za-z0-9_]*=", ln) for ln in lines):
            for ln in lines:
                k, v = re.sub(r"^export\s+", "", ln).split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                env[k.strip()] = v
            return env
        data = self._parse_vars(text, "environment")
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                self.error(f"environment: {k} must be a string, not a {type(v).__name__}")
                continue
            env[str(k)] = "" if v is None else str(v).lower() if isinstance(v, bool) else str(v)
        return env

    def load_file(self, path):
        try:
            return load_yaml(self.vfs.read(path)), None
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    # ---------------------------------------------------------- inventory vars
    def inv_layers(self, host):
        groups = self.inv.sorted_groups_of(host)
        g_inv, g_files, h_files = {}, {}, {}
        for g in groups:
            g_inv.update(self.inv.groups[g]["vars"])
            for p in self.varfiles["group_vars"].get(g, []):
                d, err = self.load_file(p)
                if err:
                    self.error(f"{p}: {err}")
                elif isinstance(d, dict):
                    g_files.update(d)
        for p in self.varfiles["host_vars"].get(host, []):
            d, err = self.load_file(p)
            if err:
                self.error(f"{p}: {err}")
            elif isinstance(d, dict):
                h_files.update(d)
        return [
            ("inventory group vars", g_inv),
            ("group_vars/ files", g_files),
            ("inventory host vars", dict(self.inv.hosts.get(host, {}))),
            ("host_vars/ files", h_files),
        ]

    def facts_layer(self):
        if not self.mock_facts:
            return {}
        facts = {(k[8:] if k.startswith("ansible_") else k): v for k, v in self.mock_facts.items()}
        out = {"ansible_facts": facts}
        out.update({f"ansible_{k}": v for k, v in facts.items()})
        return out

    def magic(self, host, play=None, frame=None):
        groups = self.inv.groups_magic()
        hosts = play.hosts if play else [host]
        m = {
            "inventory_hostname": host,
            "inventory_hostname_short": host.split(".")[0],
            "group_names": sorted(g for g in self.inv.groups_of(host) if g != "all"),
            "groups": groups,
            "omit": OMIT,
            "playbook_dir": play.pbdir if play else posixpath.dirname(self.entry or ""),
            "inventory_file": self.inv_path,
            "inventory_dir": posixpath.dirname(self.inv_path) if self.inv_path else None,
            "ansible_check_mode": False,
            "ansible_diff_mode": False,
            "ansible_run_tags": ["all"],
            "ansible_skip_tags": [],
            "ansible_version": {"full": "2.19.0", "major": 2, "minor": 19, "revision": 0, "string": "2.19.0"},
            "ansible_play_hosts": hosts,
            "ansible_play_hosts_all": hosts,
            "ansible_play_batch": hosts,
            "play_hosts": hosts,
            "ansible_play_name": play.name if play else None,
            "ansible_play_role_names": play.role_names if play else [],
            "ansible_role_names": play.role_names if play else [],
        }
        if frame and frame.role:
            m.update(role_name=frame.role.name, ansible_role_name=frame.role.name, role_path=frame.role.path,
                     ansible_parent_role_names=list(reversed(frame.parent_roles)),
                     ansible_parent_role_paths=[])
        return m

    def host_scope(self, h):
        """Scope for hostvars[other_host]: inventory, facts, magic, extra."""
        if h not in self._hs_cache:
            layers = self.inv_layers(h) + [("magic", self.magic(h)), ("extra vars", self.extra)]
            self._hs_cache[h] = VarScope(self.tp, layers, facts_runtime=True)
        return self._hs_cache[h]

    def scope(self, play, frame, loopvars=None):
        role = frame.role
        rd = dict(play.role_defaults)
        rv = dict(play.role_vars)
        if role:
            rd.update(role.defaults)
            rv.update(role.vars)
        layers = [("role defaults", rd)] + self.inv_layers(self.host) + [
            ("facts (mock)", self.facts_layer()),
            ("play vars", play.vars),
            ("vars_prompt", play.prompt),
            ("vars_files", play.vars_files),
            ("role vars", rv),
            ("block vars", frame.block_vars),
            ("include_vars", self.host_include_vars),
            ("set_fact / register", self.host_facts),
            ("role / include params", frame.params),
            ("loop", {**frame.loopvars, **(loopvars or {})}),
        ]
        magic = self.magic(self.host, play, frame)
        holder = {}
        magic["hostvars"] = HostVars(self, self.host, lambda: holder["s"])
        layers += [("magic", magic), ("extra vars", self.extra)]
        s = VarScope(self.tp, layers, facts_runtime=play.gather)
        holder["s"] = s
        return s

    def task_scope(self, play, frame, task_vars, loopvars=None):
        s = self.scope(play, frame, loopvars)
        if task_vars:
            # task vars sit just above block vars
            i = self._idx_after(s, ("block vars", "role vars", "vars_files", "vars_prompt", "play vars"))
            s.layers.insert(i, ("task vars", task_vars))
        return s

    @staticmethod
    def _idx_after(s, names):
        ln = [n for n, _ in s.layers]
        for n in names:
            if n in ln:
                return ln.index(n) + 1
        return 0

    # ---------------------------------------------------------- file helpers
    def search_dirs(self, kind, play, frame):
        r = frame.role.path if frame.role else None
        d, pb = frame.dir, play.pbdir if play else ""
        sub = {"template": "templates", "file": "files", "tasks": "tasks", "vars": "vars"}[kind]
        dirs = []
        if r:
            dirs += [posixpath.join(r, sub), r]
        dirs += [posixpath.join(d, sub), d, posixpath.join(pb, sub), pb]
        return dirs

    def _ctx(self):
        return getattr(self, "_cur", (None, Frame()))

    def file_lookup(self, name, terms, kw, scope):
        play, frame = self._ctx()
        kind = "template" if name == "template" else "file"
        dirs = self.search_dirs(kind, play, frame) if play else [""]
        if name == "fileglob":
            return [p for t in terms for p in self.vfs.glob(str(t), dirs)]
        if name == "first_found":
            files = []
            for t in terms:
                if isinstance(t, Mapping):
                    for f in t.get("files", []):
                        for p in (t.get("paths") or [""]):
                            files.append(posixpath.join(p, f))
                else:
                    files.append(str(t))
            for f in files:
                p, _ = self.vfs.find(f, dirs)
                if p:
                    return [p]
            if kw.get("skip"):
                return []
            raise FileNotFoundError(f"first_found: none of {files} found in project files")
        out = []
        for t in terms:
            p, tried = self.vfs.find(str(t), dirs)
            if not p:
                raise FileNotFoundError(f"could not locate file in lookup: {t} (tried {', '.join(tried[:4])})")
            content = self.vfs.read(p)
            if name == "template":
                content = self.tp.render_str(content, scope)
            elif kw.get("rstrip", True):
                content = content.rstrip()
            out.append(content)
        return out

    def sequence(self, terms, kw):
        spec = " ".join(map(str, terms))
        args = dict(re.findall(r"(\w+)=(\S+)", spec))
        args.update({k: str(v) for k, v in kw.items()})
        m = re.match(r"^\s*(?:(\d+)-)?(\d+)(?:/(\d+))?(?::(.+))?\s*$", spec) if "=" not in spec else None
        if m:
            start, end, stride, fmt = int(m.group(1) or 1), int(m.group(2)), int(m.group(3) or 1), m.group(4) or "%d"
        else:
            start = int(args.get("start", 1))
            stride = int(args.get("stride", 1))
            end = int(args["end"]) if "end" in args else start + int(args.get("count", 0)) * stride - stride
            fmt = args.get("format", "%d")
        return [fmt % i for i in range(start, end + (1 if stride > 0 else -1), stride)]

    # ---------------------------------------------------------- run
    def run(self):
        plays = []
        if not self.entry or not self.vfs.exists(self.entry):
            self.error(f"entry playbook not found: {self.entry}")
        else:
            self.walk_playbook(self.entry, plays, 0)
        return {
            "meta": {
                "host": self.host,
                "hosts": sorted(self.inv.hosts),
                "groups": {g: sorted(self.inv.members(g)) for g in sorted(self.inv.groups)},
                "host_groups": sorted(self.inv.groups_of(self.host)),
                "entry": self.entry,
                "inventory": self.inv_path,
            },
            "plays": plays,
            "diagnostics": self.diag,
        }

    def walk_playbook(self, path, plays, depth):
        data, err = self.load_file(path)
        if err:
            self.error(f"YAML error: {err}", path)
            return
        if not isinstance(data, list):
            self.error("a playbook must be a list of plays", path)
            return
        pbdir = posixpath.dirname(path)
        for i, pl in enumerate(data):
            if not isinstance(pl, dict):
                self.error(f"play #{i + 1} is not a mapping", path)
                continue
            imp = pl.get("import_playbook") or pl.get("ansible.builtin.import_playbook")
            if imp is not None:
                tmp = Play("import_playbook", pbdir)
                s = self.scope(tmp, Frame(file=path))
                with tracing():
                    target = self.tp.template(imp, s)
                p, tried = self.vfs.find(str(target), [pbdir])
                node = {"kind": "import_playbook", "raw": J(imp), "target": J(target), "found": p,
                        "file": path, "line": line_of(pl)}
                plays.append(node)
                if not p:
                    self.error(f"import_playbook: file not found: {target}", f"{path}:{line_of(pl)}")
                elif depth < MAX_DEPTH:
                    self.walk_playbook(p, plays, depth + 1)
                continue
            plays.append(self.walk_play(pl, path, pbdir, i))

    # ---------------------------------------------------------- play
    def walk_play(self, pl, path, pbdir, idx):
        name_raw = pl.get("name") or f"play #{idx + 1}"
        play = Play(str(name_raw), pbdir)
        frame = Frame(file=path)
        where = f"{path}:{line_of(pl)}"
        play.vars = dict(pl.get("vars") or {}) if isinstance(pl.get("vars") or {}, dict) else {}
        gf = pl.get("gather_facts", True)
        play.gather = True if (isinstance(gf, str) and "{{" in gf) else to_bool(gf)
        play.collections = pl.get("collections") or []
        for vp in pl.get("vars_prompt") or []:
            if isinstance(vp, dict) and "name" in vp:
                play.prompt[vp["name"]] = vp["default"] if "default" in vp else Runtime(f"prompt:{vp['name']}")

        # hosts
        s0 = self.scope(play, frame)
        with tracing() as th:
            hosts_r = self.tp.template(pl.get("hosts", ""), s0)
        matched = self.inv.match(hosts_r if not isinstance(hosts_r, Runtime) else "")
        play.hosts = matched
        targeted = self.host in matched
        node = {
            "kind": "play", "id": self._id(), "name_raw": J(name_raw), "file": path, "line": line_of(pl),
            "hosts_raw": J(pl.get("hosts")), "hosts": J(hosts_r), "matched": matched, "targeted": targeted,
            "gather_facts": play.gather, "hosts_trace": trace_json(th), "vars_files": [], "roles": [],
            "sections": {}, "handlers": [], "keywords": [],
        }
        if "hosts" not in pl:
            self.error("play has no 'hosts' keyword", where)
        if not targeted:
            self.info(f"play '{name_raw}' does not target {self.host}; analysed for reference", where)
        for k in ("become", "become_user", "remote_user", "connection", "serial", "strategy", "any_errors_fatal",
                  "max_fail_percentage", "order", "environment", "tags", "collections", "module_defaults"):
            if k in pl:
                with tracing() as tk:
                    v = self.tp.template(pl[k], s0)
                node["keywords"].append({"key": k, "raw": J(pl[k]), "value": J(v), "trace": trace_json(tk)})

        # vars_files
        for vf in pl.get("vars_files") or []:
            cands = vf if isinstance(vf, list) else [vf]
            entry = {"raw": J(vf), "loaded": None, "tried": []}
            for c in cands:
                s = self.scope(play, frame)
                with tracing() as tv:
                    name = self.tp.template(c, s)
                if not tv.clean:
                    entry["tried"].append(f"{name} (unresolved: {', '.join(tv.undefined + tv.runtime)})")
                    continue
                p, tried = self.vfs.find(str(name), [pbdir])
                entry["tried"] += tried
                if p:
                    d, err = self.load_file(p)
                    if err:
                        self.error(f"vars_files {p}: {err}", where)
                    elif isinstance(d, dict):
                        play.vars_files.update(d)
                        entry["loaded"] = p
                        entry["keys"] = list(d)
                    break
            if not entry["loaded"]:
                self.error(f"vars_files: could not find {vf!r} in project files", where)
            node["vars_files"].append(entry)

        if play.gather:
            self.info("gather_facts is on: ansible_* facts are treated as runtime values"
                      + (" (mock facts override where given)" if self.mock_facts else ""), where)

        # body
        for sec in ("pre_tasks", "roles", "tasks", "post_tasks"):
            if sec not in pl or pl[sec] is None:
                continue
            if sec == "roles":
                items = []
                for r in pl["roles"]:
                    items.append(self.walk_play_role(r, play, frame, path))
                node["sections"]["roles"] = items
            else:
                node["sections"][sec] = self.walk_tasks(pl[sec], play, frame)
        for h in pl.get("handlers") or []:
            play.handlers.append((h, frame))
        node["handlers"] = self.walk_handlers(play)
        node["notified"] = play.notified
        node["vars"] = self.snapshot(play, frame)
        return node

    def _id(self):
        self.ids += 1
        return f"n{self.ids}"

    def snapshot(self, play, frame):
        s = self.scope(play, frame)
        out = []
        skip_layers = {"magic"}
        for k in s.keys_all():
            src, raw = s.find(k)
            if src in skip_layers:
                continue
            with tracing() as t:
                v = s[k]
            out.append({"name": k, "source": src, "shadowed": [x for x in s.sources(k) if x != src],
                        "raw": J(raw), "value": J(v), "trace": trace_json(t)})
        return out

    # ---------------------------------------------------------- roles
    def find_role(self, name, play, frame):
        name = str(name)
        if "/" in name:
            cands = [posixpath.join(play.pbdir, name), name]
        else:
            cands = []
            if frame.role:
                cands.append(posixpath.join(posixpath.dirname(frame.role.path), name))
            cands += [posixpath.join(play.pbdir, "roles", name), posixpath.join("roles", name),
                      posixpath.join(play.pbdir, name)]
        for c in cands:
            if self.vfs.isdir(c):
                return c.rstrip("/") if c else c
        tail = f"roles/{name}/"
        for k in self.vfs.files:
            if k.startswith(tail) or ("/" + tail) in k:
                return k[: k.index(tail) + len(tail) - 1]
        return None

    def walk_play_role(self, r, play, frame, path):
        if isinstance(r, str):
            spec = {"role": r}
        elif isinstance(r, dict):
            spec = dict(r)
        else:
            return {"kind": "role", "id": self._id(), "error": f"bad role entry {r!r}"}
        rname = spec.pop("role", None) or spec.pop("name", None)
        whens = list(frame.whens)
        if "when" in spec:
            w = spec.pop("when")
            whens += [(x, f"role {rname}") for x in (w if isinstance(w, list) else [w])]
        rvars = spec.pop("vars", None) or {}
        for k in ("tags", "become", "become_user", "delegate_to", "ignore_errors", "environment",
                  "any_errors_fatal", "no_log"):
            spec.pop(k, None)
        params = {**frame.params, **rvars, **spec}
        return self.run_role(rname, play, frame.child(whens=whens, params=params), r, path, "roles:")

    def run_role(self, rname, play, frame, spec_raw, path, how, tasks_from="main", vars_from="main",
                 defaults_from="main", handlers_from="main", public=True):
        s = self.scope(play, frame)
        with tracing():
            rname_r = str(self.tp.template(rname, s))
        node = {"kind": "role", "id": self._id(), "name": rname_r, "how": how, "file": path,
                "line": line_of(spec_raw), "params": [], "defaults": [], "vars": [], "children": [],
                "deps": [], "whens": [{"expr": J(e), "origin": o} for e, o in frame.whens]}
        rpath = self.find_role(rname_r, play, frame)
        node["path"] = rpath
        if not rpath:
            node["found"] = False
            self.error(f"role '{rname_r}' not found in project files (looked in roles/, playbook dir)",
                       f"{path}:{line_of(spec_raw)}", node["id"])
            return node
        node["found"] = True
        key = (rname_r, repr(sorted((k, repr(v)) for k, v in frame.params.items())))
        if key in play.roles_seen and how != "include_role":
            node["note"] = "already ran in this play with same params (allow_duplicates: false): skipped"
            node["skipped"] = True
            return node
        play.roles_seen.add(key)
        if rname_r not in play.role_names:
            play.role_names.append(rname_r)
        role = Role(rname_r, rpath)
        for attr, sub, stem in (("defaults", "defaults", defaults_from), ("vars", "vars", vars_from)):
            p = self.vfs.find_yaml([posixpath.join(rpath, sub)], stem)
            if p:
                d, err = self.load_file(p)
                if err:
                    self.error(f"{p}: {err}", p)
                elif isinstance(d, dict):
                    setattr(role, attr, d)
                    node[attr] = [{"name": k, "raw": J(v), "file": p} for k, v in d.items()]
        if public:
            play.role_defaults.update(role.defaults)
            play.role_vars.update(role.vars)
        rframe = frame.child(role=role, parent_roles=frame.parent_roles + ([frame.role.name] if frame.role else []),
                             depth=frame.depth + 1)
        for k, v in frame.params.items():
            node["params"].append({"name": k, "raw": J(v)})
        # meta dependencies
        mp = self.vfs.find_yaml([posixpath.join(rpath, "meta")], "main")
        if mp:
            meta, err = self.load_file(mp)
            if isinstance(meta, dict):
                for dep in meta.get("dependencies") or []:
                    if isinstance(dep, str):
                        dspec = {"role": dep}
                    elif isinstance(dep, dict):
                        dspec = dict(dep)
                    else:
                        continue
                    dname = dspec.pop("role", None) or dspec.pop("name", None)
                    dvars = dspec.pop("vars", None) or {}
                    dwhen = dspec.pop("when", None)
                    dspec.pop("tags", None)
                    wh = list(frame.whens) + ([(dwhen, f"dependency {dname}")] if dwhen is not None else [])
                    node["deps"].append(self.run_role(dname, play, rframe.child(params={**dvars, **dspec}, whens=wh),
                                                      dep, mp, "dependency"))
        hp = self.vfs.find_yaml([posixpath.join(rpath, "handlers")], handlers_from)
        if hp:
            hd, err = self.load_file(hp)
            if isinstance(hd, list):
                for h in hd:
                    play.handlers.append((h, rframe.child(file=hp, whens=[], params=frame.params)))
        tp = self.vfs.find_yaml([posixpath.join(rpath, "tasks")], tasks_from)
        if not tp:
            if tasks_from != "main":
                self.error(f"role '{rname_r}': tasks_from '{tasks_from}' not found", path, node["id"])
            node["note"] = "role has no tasks file"
            return node
        node["tasks_file"] = tp
        tasks, err = self.load_file(tp)
        if err:
            self.error(f"{tp}: {err}", tp, node["id"])
            return node
        node["children"] = self.walk_tasks(tasks or [], play, rframe.child(file=tp))
        return node

    # ---------------------------------------------------------- tasks
    def walk_tasks(self, tasks, play, frame):
        out = []
        if not isinstance(tasks, list):
            self.error("task list must be a list", frame.file)
            return out
        for t in tasks:
            if not isinstance(t, dict):
                self.error(f"task is not a mapping: {t!r}", frame.file)
                continue
            if any(k in t for k in BLOCK_KW):
                out.append(self.walk_block(t, play, frame))
            else:
                out.append(self.walk_task(t, play, frame))
        return out

    def walk_block(self, b, play, frame):
        where = f"{frame.file}:{line_of(b)}"
        bvars = {**frame.block_vars, **(b.get("vars") or {})}
        s = self.scope(play, frame.child(block_vars=bvars))
        whens = list(frame.whens)
        node = {"kind": "block", "id": self._id(), "name_raw": J(b.get("name")), "file": frame.file,
                "line": line_of(b), "sections": {}, "vars": [{"name": k, "raw": J(v)} for k, v in
                                                              (b.get("vars") or {}).items()], "when": []}
        own = b.get("when")
        cap = frame.cap
        if own is not None:
            for w in own if isinstance(own, list) else [own]:
                res, t, warn = self.tp.conditional(w, s)
                node["when"].append({"expr": J(w), "result": res, "trace": trace_json(t), "warn": warn})
                whens.append((w, "block"))
                cap = worst(cap, self._status_of(res))
        node["status"] = cap
        child = frame.child(block_vars=bvars, whens=whens, cap=cap)
        for sec in ("block", "rescue", "always"):
            if sec in b and b[sec]:
                f = child
                if sec == "rescue":
                    f = child.child(cap=worst(cap, "conditional"), cap_note="rescue: runs only if a block task fails")
                node["sections"][sec] = self.walk_tasks(b[sec], play, f)
        return node

    @staticmethod
    def _status_of(res):
        return {True: "run", False: "skipped", "unknown": "conditional", "error": "error"}.get(res, "run")

    def resolve_action(self, task):
        notes = []
        local = False
        if "action" in task or "local_action" in task:
            key = "action" if "action" in task else "local_action"
            local = key == "local_action"
            val = task[key]
            if isinstance(val, dict):
                val = dict(val)
                mod = val.pop("module", None)
                args = val
            else:
                mod, _, rest = str(val).strip().partition(" ")
                args, n = parse_kv(rest, fqcn(mod)[1] in FREE_FORM)
                notes += n
            others = [k for k in task if k not in TASK_KW and not k.startswith("with_")]
            if others:
                notes.append(f"conflicting action statements: {key}, {', '.join(others)}")
        else:
            cands = [k for k in task if k not in TASK_KW and not k.startswith("with_")]
            if not cands:
                return None, {}, ["no module/action detected in task"], False
            if len(cands) > 1:
                notes.append(f"conflicting action statements: {', '.join(cands)} (using '{cands[0]}')")
            mod = cands[0]
            val = task[mod]
            if val is None:
                args = {}
            elif isinstance(val, dict):
                args = dict(val)
            elif isinstance(val, str):
                args, n = parse_kv(val, fqcn(mod)[1] in FREE_FORM)
                notes += n
            else:
                args = {"_raw_params": val}
        targs = task.get("args")
        if isinstance(targs, dict):
            args = {**targs, **args}
        return mod, args, notes, local

    def walk_task(self, task, play, frame):
        self._cur = (play, frame)
        where = f"{frame.file}:{line_of(task)}"
        mod, args, notes, local = self.resolve_action(task)
        full, short, kind = fqcn(mod) if mod else (None, None, None)
        node = {"kind": "task", "id": self._id(), "file": frame.file, "line": line_of(task),
                "name_raw": J(task.get("name")), "module": mod, "fqcn": full, "module_kind": kind,
                "notes": list(notes), "role": frame.role.name if frame.role else None, "iterations": [],
                "keywords": [], "after_run": [], "inherited_when": [{"expr": J(e), "origin": o} for e, o in frame.whens],
                "handler": frame.handler}
        for n in notes:
            self.warn(n, where, node["id"])
        if not mod:
            node["status"] = "error"
            self.error("no module/action detected in task", where, node["id"])
            return node
        if kind == "unknown":
            node["notes"].append("short name is not ansible.builtin: resolved through 'collections' keyword or "
                                 "ansible.legacy (custom module / action plugin)")
        if local:
            node["keywords"].append({"key": "delegate_to", "raw": "localhost (local_action)", "value": "localhost"})
        tvars = task.get("vars") or {}
        base = self.task_scope(play, frame, tvars)
        # name: templated without loop vars
        with tracing() as tn:
            name = self.tp.template(task.get("name"), base) if task.get("name") is not None else None
        node["name"] = J(name) if tn.clean or name is None else J(task.get("name"))
        # loop
        items, linfo = self.eval_loop(task, base, where, node)
        node["loop"] = linfo
        lc = task.get("loop_control") or {}
        loop_var = lc.get("loop_var", "item")
        index_var = lc.get("index_var")
        status_all = []
        is_include = short in ("include_tasks", "import_tasks", "include_role", "import_role")
        iter_list = items if items is not None else [None]
        if is_include and items is not None and len(iter_list) > MAX_INCLUDE_LOOP:
            node["notes"].append(f"include loop truncated to {MAX_INCLUDE_LOOP} iterations")
            iter_list = iter_list[:MAX_INCLUDE_LOOP]
        elif len(iter_list) > MAX_ITEMS:
            node["notes"].append(f"loop truncated to {MAX_ITEMS} of {len(iter_list)} iterations")
            iter_list = iter_list[:MAX_ITEMS]
        if short == "import_tasks" or short == "import_role":
            if items is not None:
                self.error(f"{short} cannot be used with a loop (use include_*)", where, node["id"])
        for i, item in enumerate(iter_list):
            lv = {}
            if items is not None:
                lv = {loop_var: item, "ansible_loop_var": loop_var}
                if index_var:
                    lv[index_var] = i
                    lv["ansible_index_var"] = index_var
                if lc.get("extended"):
                    n = len(items)
                    lv["ansible_loop"] = {"index": i + 1, "index0": i, "first": i == 0, "last": i == n - 1,
                                          "length": n, "revindex": n - i, "revindex0": n - i - 1,
                                          "allitems": items, "previtem": items[i - 1] if i else None,
                                          "nextitem": items[i + 1] if i < n - 1 else None}
            s = self.task_scope(play, frame, tvars, lv)
            it = self.eval_iteration(task, short, args, s, play, frame, lv, items is not None, loop_var, lc, where, node)
            node["iterations"].append(it)
            status_all.append(it["status"])
        # combined status
        if "error" in status_all:
            st = "error"
        elif "run" in status_all:
            st = "run"
        elif "conditional" in status_all:
            st = "conditional"
        else:
            st = "skipped"
        if items is not None and not iter_list:
            node["notes"].append("loop is empty: task does nothing")
        st = worst(st, frame.cap)
        if frame.cap != "run" and frame.cap_note:
            node["notes"].append(frame.cap_note)
        node["status"] = st
        # keywords
        for k in SHOW_KW:
            if k in task:
                with tracing() as tk:
                    v = self.tp.template(task[k], base)
                node["keywords"].append({"key": k, "raw": J(task[k]), "value": J(v), "trace": trace_json(tk)})
        for k in AFTER_RUN_KW:
            if k in task:
                node["after_run"].append({"key": k, "raw": J(task[k])})
        if "register" in task:
            reg = str(task["register"])
            node["register"] = reg
            if st == "skipped" and items is None:
                self.host_facts[reg] = {"changed": False, "skipped": True,
                                        "skip_reason": "Conditional result was False", "false_condition": "when"}
            else:
                self.host_facts[reg] = Runtime(reg)
        if "notify" in task and st != "skipped":
            with tracing():
                nt = self.tp.template(task["notify"], base)
            nt = nt if isinstance(nt, list) else [nt]
            node["notify"] = J(nt)
            for n in nt:
                prev = play.notified.get(str(n))
                play.notified[str(n)] = "yes" if prev == "yes" else "maybe"
        # surface trace problems as diagnostics
        und, rt, errs = set(), set(), set()
        for it in node["iterations"]:
            for a in it["args"]:
                und |= set(a["trace"]["undefined"])
                errs |= set(a["trace"]["errors"])
                rt |= set(a["trace"]["runtime"])
            for w in it["when"]:
                und |= set(w["trace"]["undefined"])
                errs |= set(w["trace"]["errors"])
        label = node["name"] if isinstance(node["name"], str) else (full or "?")
        for u in sorted(und):
            self.error(f"undefined variable '{u}' in task '{label}'", where, node["id"])
        for e in sorted(errs):
            if "is undefined" not in e:
                self.error(f"{e} in task '{label}'", where, node["id"])
        return node

    def eval_loop(self, task, scope, where, node):
        lk = [k for k in task if k == "loop" or k.startswith("with_")]
        if not lk:
            return None, None
        key = lk[0]
        raw = task[key]
        with tracing() as t:
            if key == "loop":
                val = self.tp.template(raw, scope)
                if isinstance(val, Runtime):
                    items = [Runtime(f"{val._p}[*]")]
                elif isinstance(val, SymUndefined) or val is None:
                    items = []
                elif isinstance(val, str):
                    self.error("Invalid data passed to 'loop', it requires a list, got a string", where, node["id"])
                    items = [val]
                elif isinstance(val, Mapping):
                    self.error("Invalid data passed to 'loop', it requires a list, got a dict (use dict2items)",
                               where, node["id"])
                    items = []
                else:
                    items = list(val)
            else:
                lookup = key[5:]
                val = self.tp.template(raw, scope)
                if isinstance(val, Runtime):
                    items = [Runtime(f"{val._p}[*]")]
                else:
                    terms = val if isinstance(val, list) else [val]
                    try:
                        if lookup == "items":
                            items = []
                            for x in terms:
                                items += x if isinstance(x, list) else [x]
                        elif lookup == "list":
                            items = list(terms)
                        elif lookup == "dict":
                            d = val if isinstance(val, Mapping) else (terms[0] if terms else {})
                            items = [{"key": k, "value": v} for k, v in d.items()]
                        elif lookup == "indexed_items":
                            items = [[i, x] for i, x in enumerate(terms)]
                        elif lookup == "together":
                            from .filters import f_zip_longest  # noqa: PLC0415
                            items = f_zip_longest(*terms)
                        elif lookup in ("nested", "cartesian"):
                            from .filters import f_product  # noqa: PLC0415
                            items = f_product(*terms)
                        elif lookup == "subelements":
                            from .filters import f_subelements  # noqa: PLC0415
                            items = f_subelements(terms[0], terms[1])
                        elif lookup == "sequence":
                            items = self.sequence(terms, {})
                        elif lookup in ("fileglob", "first_found", "file", "template"):
                            items = self.file_lookup(lookup, terms, {}, scope)
                        else:
                            items = [Runtime(f"with_{lookup}[*]")]
                    except Exception as e:  # noqa: BLE001
                        self.error(f"{key}: {e}", where, node["id"])
                        items = []
        rt = bool(t.runtime) or isinstance(val, Runtime)
        info = {"key": key, "raw": J(raw), "count": len(items), "runtime": rt,
                "trace": trace_json(t), "loop_control": J(task.get("loop_control"))}
        for u in t.undefined:
            self.error(f"undefined variable '{u}' in {key}", where, node["id"])
        return items, info

    def eval_iteration(self, task, short, args, s, play, frame, lv, looped, loop_var, lc, where, node):
        it = {"item": J(lv.get(loop_var)) if looped else None, "label": None, "when": [], "status": "run",
              "args": [], "extra": {}, "children": None}
        if looped and lc.get("label") is not None:
            with tracing():
                it["label"] = J(self.tp.template(lc["label"], s))
        # conditions: inherited (import/static) then own
        st = "run"
        conds = []
        own = task.get("when")
        if own is not None and short not in ("import_tasks", "import_role"):
            # import_* is static: its 'when' is copied onto every imported task instead
            conds += [(c, "task") for c in (own if isinstance(own, list) else [own])]
        for expr, origin in frame.whens + conds:
            res, t, warn = self.tp.conditional(expr, s)
            it["when"].append({"expr": J(expr), "origin": origin, "result": res, "trace": trace_json(t), "warn": warn})
            if warn:
                self.warn(warn + f": {expr!r}", where, node["id"])
            st = worst(st, self._status_of(res))
            if res is False:
                break
        st = worst(st, frame.cap)
        it["status"] = st
        # args
        rendered = {}
        for k, raw in args.items():
            with tracing() as t:
                v = self.tp.template(raw, s)
            omitted = is_omit(v)
            v2 = strip_omit(v)
            rendered[k] = v2
            it["args"].append({"key": k, "raw": J(raw), "value": J(v2), "omitted": omitted,
                               "type": _type(v2), "trace": trace_json(t)})
        if st == "skipped":
            return it
        self.module_effects(short, task, rendered, s, play, frame, it, where, node, lv)
        return it

    # ---------------------------------------------------------- module effects
    def module_effects(self, short, task, a, s, play, frame, it, where, node, lv):
        cond = it["status"] != "run"
        if short == "set_fact":
            facts = {k: v for k, v in a.items() if k not in ("cacheable", "_raw_params")}
            self.host_facts.update(facts)
            it["extra"]["sets"] = list(facts)
            if cond:
                it["extra"]["note"] = "set_fact applied although its condition is not known statically"
        elif short == "include_vars":
            self.do_include_vars(a, s, play, frame, it, where, node)
        elif short == "debug":
            if "var" in a:
                with tracing() as t:
                    out = self.tp.render_str("{{ " + str(a["var"]) + " }}", s)
                it["extra"]["debug"] = {"var": a["var"], "value": J(out), "trace": trace_json(t)}
            else:
                it["extra"]["debug"] = {"msg": J(a.get("msg", "Hello world!"))}
        elif short == "assert":
            that = a.get("that", [])
            res = []
            for c in that if isinstance(that, list) else [that]:
                r, t, _ = self.tp.conditional(c, s)
                res.append({"expr": J(c), "result": r, "trace": trace_json(t)})
            it["extra"]["assert"] = res
            if any(x["result"] is False for x in res):
                it["extra"]["fails"] = J(a.get("fail_msg") or a.get("msg") or "Assertion failed")
                self.warn(f"assert would fail: {it['extra']['fails']}", where, node["id"])
        elif short == "fail":
            it["extra"]["fails"] = J(a.get("msg", "Failed as requested from task"))
            if not cond:
                self.warn(f"fail task would stop host {self.host}: {it['extra']['fails']}", where, node["id"])
        elif short == "template":
            self.do_template(a, s, play, frame, it, where, node)
        elif short in ("include_tasks", "import_tasks"):
            fname = a.get("file") or a.get("_raw_params")
            p, tried = self.vfs.find(str(fname), self.search_dirs("tasks", play, frame)) if fname else (None, [])
            it["extra"]["include"] = {"file": J(fname), "found": p, "tried": tried[:6]}
            if not p:
                self.error(f"{short}: file not found: {fname}", where, node["id"])
                return
            if frame.depth > MAX_DEPTH:
                self.error("include depth limit reached (recursive include?)", where, node["id"])
                return
            tasks, err = self.load_file(p)
            if err:
                self.error(f"{p}: {err}", where, node["id"])
                return
            tvars = task.get("vars") or {}
            if short == "import_tasks":
                own = task.get("when")
                wh = list(frame.whens) + [(c, f"import_tasks {fname}") for c in
                                          ((own if isinstance(own, list) else [own]) if own is not None else [])]
                f = frame.child(file=p, whens=wh, block_vars={**frame.block_vars, **tvars}, depth=frame.depth + 1)
            else:
                f = frame.child(file=p, whens=[], params={**frame.params, **tvars},
                                loopvars={**frame.loopvars, **lv}, depth=frame.depth + 1,
                                cap=worst(frame.cap, it["status"]))
            it["children"] = self.walk_tasks(tasks or [], play, f)
            self._cur = (play, frame)
        elif short in ("include_role", "import_role"):
            rname = a.get("name")
            if not rname:
                self.error(f"{short}: 'name' is required", where, node["id"])
                return
            tvars = task.get("vars") or {}
            own = task.get("when")
            wh = list(frame.whens)
            if short == "import_role" and own is not None:
                wh += [(c, f"import_role {rname}") for c in (own if isinstance(own, list) else [own])]
            f = frame.child(params={**frame.params, **tvars}, whens=wh if short == "import_role" else [],
                            loopvars={**frame.loopvars, **lv},
                            cap=worst(frame.cap, it["status"]) if short == "include_role" else frame.cap)
            rn = self.run_role(rname, play, f, task, frame.file, short,
                               tasks_from=str(a.get("tasks_from", "main")), vars_from=str(a.get("vars_from", "main")),
                               defaults_from=str(a.get("defaults_from", "main")),
                               handlers_from=str(a.get("handlers_from", "main")),
                               public=short == "import_role" or to_bool(a.get("public", False)))
            it["children"] = [rn]
            self._cur = (play, frame)
        elif short == "meta":
            it["extra"]["meta"] = J(a.get("_raw_params"))
        elif short in ("add_host", "group_by"):
            it["extra"]["note"] = f"{short} changes the in-memory inventory at runtime; not modelled here"
        elif short == "copy" and "content" in a:
            it["extra"]["content"] = J(a["content"])

    def do_include_vars(self, a, s, play, frame, it, where, node):
        fname = a.get("file") or a.get("_raw_params")
        dirs = self.search_dirs("vars", play, frame)
        loaded = {}
        paths = []
        if a.get("dir"):
            base = str(a["dir"])
            for d in dirs:
                pre = posixpath.normpath(posixpath.join(d, base)) + "/"
                found = sorted(k for k in self.vfs.files if k.startswith(pre) and k.endswith((".yml", ".yaml", ".json")))
                if found:
                    paths = found
                    break
        elif fname:
            p, tried = self.vfs.find(str(fname), dirs)
            if p:
                paths = [p]
            else:
                self.error(f"include_vars: file not found: {fname}", where, node["id"])
        for p in paths:
            d, err = self.load_file(p)
            if err:
                self.error(f"{p}: {err}", where, node["id"])
            elif isinstance(d, dict):
                loaded.update(d)
        if a.get("name"):
            self.host_include_vars[str(a["name"])] = loaded
        else:
            self.host_include_vars.update(loaded)
        it["extra"]["include_vars"] = {"files": paths, "keys": list(loaded), "name": J(a.get("name"))}

    def do_template(self, a, s, play, frame, it, where, node):
        src = a.get("src")
        if not src:
            return
        p, tried = self.vfs.find(str(src), self.search_dirs("template", play, frame))
        info = {"src": J(src), "found": p, "tried": tried[:6]}
        it["extra"]["template"] = info
        if not p:
            self.error(f"template: src not found in project files: {src}", where, node["id"])
            return
        extra = {"ansible_managed": "Ansible managed", "template_host": "controller", "template_path": p, "template_fullpath": p,
                 "template_destpath": a.get("dest"), "template_uid": "ansible",
                 "template_run_date": Runtime("template_run_date")}
        content = self.vfs.read(p)
        with tracing() as t:
            out = self.tp.render_str(content, s, extra) if not isinstance(content, Unsafe) else content
        info["output"] = J(out if isinstance(out, str) else str(out))
        info["trace"] = trace_json(t)
        for u in t.undefined:
            self.error(f"undefined variable '{u}' in template {p}", where, node["id"])
        for e in t.errors:
            if "is undefined" not in e:
                self.error(f"{e} in template {p}", where, node["id"])

    # ---------------------------------------------------------- handlers
    def walk_handlers(self, play):
        out = []
        for h, frame in play.handlers:
            if not isinstance(h, dict):
                continue
            s = self.scope(play, frame)
            with tracing():
                name = self.tp.template(h.get("name"), s) if h.get("name") else None
                listen = self.tp.template(h.get("listen"), s) if h.get("listen") else []
            keys = [str(name)] if name else []
            keys += [str(x) for x in (listen if isinstance(listen, list) else [listen])]
            state = None
            for k in keys:
                v = play.notified.get(k)
                if v == "yes" or (v and not state):
                    state = v
            cap, note = "run", None
            if not state:
                cap, note = "skipped", "not notified by any task"
            elif state == "maybe":
                cap, note = "conditional", "notified only if the notifying task reports 'changed'"
            n = self.walk_task(h, play, frame.child(cap=cap, cap_note=note, handler=True, whens=[]))
            n["listen"] = J(listen) if listen else None
            out.append(n)
        return out


def _type(v):
    if isinstance(v, Runtime):
        return "runtime"
    if isinstance(v, Undefined):
        return "undefined"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, Mapping):
        return "dict"
    if isinstance(v, list):
        return "list"
    if v is None:
        return "null"
    return type(v).__name__


__all__ = ["Analyzer", "LDict", "OMIT"]
