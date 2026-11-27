"""Re-implementation of common Ansible filters and tests (ansible.builtin).

Filters that need the managed host or the controller (password_hash with a
random salt, file tests, ...) return a ``Runtime`` placeholder instead of a
guess.
"""
import base64
import datetime
import hashlib
import ipaddress
import itertools
import json
import math
import ntpath
import posixpath
import re
import shlex
import uuid
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

import yaml
from jinja2 import Undefined

from .values import Runtime, SymUndefined

# --------------------------------------------------------------------------- helpers


class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (Runtime, Undefined)):
            return str(o)
        if isinstance(o, Mapping):
            return dict(o)
        if isinstance(o, (set, frozenset, tuple)):
            return list(o)
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        return str(o)


class _Dumper(yaml.SafeDumper):
    pass


def _repr_str(d, v):
    return d.represent_scalar("tag:yaml.org,2002:str", str(v))


_Dumper.add_multi_representer(Runtime, _repr_str)
_Dumper.add_multi_representer(Undefined, _repr_str)
_Dumper.add_representer(tuple, lambda d, v: d.represent_list(list(v)))
_Dumper.add_multi_representer(str, lambda d, v: d.represent_str(str(v)))
_Dumper.add_multi_representer(dict, lambda d, v: d.represent_dict(dict(v)))


def _plain(o):
    """Deep-copy into plain python types for dumping."""
    if isinstance(o, Mapping):
        return {_plain(k): _plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_plain(v) for v in o]
    return o


def to_bool(v):
    if isinstance(v, bool) or v is None:
        return bool(v)
    if isinstance(v, (int, float)):
        return v == 1
    s = str(v).strip().lower()
    return s in ("yes", "on", "1", "true", "y", "t")


# --------------------------------------------------------------------------- filters


def f_bool(v):
    return to_bool(v)


def f_to_json(v, **kw):
    kw.setdefault("ensure_ascii", False)
    return json.dumps(_plain(v), cls=_Enc, **kw)


def f_to_nice_json(v, indent=4, sort_keys=True, **kw):
    return json.dumps(_plain(v), cls=_Enc, indent=indent, sort_keys=sort_keys,
                      separators=(",", ": "), ensure_ascii=False, **kw)


def f_from_json(v):
    return json.loads(v)


def f_to_yaml(v, **kw):
    kw.setdefault("default_flow_style", None)
    return yaml.dump(_plain(v), Dumper=_Dumper, allow_unicode=True, **kw)


def f_to_nice_yaml(v, indent=4, **kw):
    return yaml.dump(_plain(v), Dumper=_Dumper, indent=indent, allow_unicode=True,
                     default_flow_style=False, **kw)


def f_from_yaml(v):
    return yaml.safe_load(v)


def f_from_yaml_all(v):
    return list(yaml.safe_load_all(v))


def _flags(ignorecase=False, multiline=False):
    fl = 0
    if ignorecase:
        fl |= re.I
    if multiline:
        fl |= re.M
    return fl


def f_regex_replace(v, pattern="", replacement="", ignorecase=False, multiline=False, count=0, mandatory_count=0):
    rx = re.compile(pattern, _flags(ignorecase, multiline))
    out, n = rx.subn(replacement, str(v), count=count)
    if mandatory_count and n != mandatory_count:
        raise ValueError(f"regex_replace: {n} matches, {mandatory_count} required")
    return out


def f_regex_search(v, regex, *groups, ignorecase=False, multiline=False):
    m = re.search(regex, str(v), _flags(ignorecase, multiline))
    if not m:
        return None
    if not groups:
        return m.group()
    out = []
    for g in groups:
        if g.startswith("\\g<"):
            out.append(m.group(g[3:-1]))
        elif g.startswith("\\"):
            out.append(m.group(int(g[1:])))
    return out


def f_regex_findall(v, regex, multiline=False, ignorecase=False):
    return re.findall(regex, str(v), _flags(ignorecase, multiline))


def f_regex_escape(v, re_type="python"):
    return re.escape(str(v))


def f_b64encode(v, encoding="utf-8"):
    return base64.b64encode(str(v).encode(encoding)).decode()


def f_b64decode(v, encoding="utf-8"):
    return base64.b64decode(str(v)).decode(encoding)


def f_hash(v, algo="sha1"):
    return hashlib.new(algo, str(v).encode()).hexdigest()


def f_checksum(v):
    return f_hash(v, "sha1")


def f_md5(v):
    return f_hash(v, "md5")


def f_password_hash(v, hashtype="sha512", salt=None, **kw):
    return Runtime(f"password_hash({hashtype})")


def f_quote(v):
    return shlex.quote(str(v))


def f_ternary(v, true_val, false_val, none_val=None):
    if v is None and none_val is not None:
        return none_val
    return true_val if v else false_val


def _merge(a, b, recursive, list_merge):
    out = dict(a)
    for k, bv in b.items():
        av = out.get(k)
        if recursive and isinstance(av, Mapping) and isinstance(bv, Mapping):
            out[k] = _merge(av, bv, recursive, list_merge)
        elif isinstance(av, list) and isinstance(bv, list) and list_merge != "replace":
            if list_merge == "keep":
                out[k] = av
            elif list_merge == "append":
                out[k] = av + bv
            elif list_merge == "prepend":
                out[k] = bv + av
            elif list_merge == "append_rp":
                out[k] = [x for x in av if x not in bv] + bv
            elif list_merge == "prepend_rp":
                out[k] = bv + [x for x in av if x not in bv]
            else:
                out[k] = bv
        else:
            out[k] = bv
    return out


def f_combine(*terms, recursive=False, list_merge="replace"):
    flat = []
    for t in terms:
        if isinstance(t, (list, tuple)):
            flat.extend(t)
        else:
            flat.append(t)
    out = {}
    for t in flat:
        if isinstance(t, Runtime):
            return t
        if not isinstance(t, Mapping):
            raise TypeError(f"combine expects dictionaries, got {type(t).__name__}")
        out = _merge(out, t, recursive, list_merge)
    return out


def f_dict2items(v, key_name="key", value_name="value"):
    if not isinstance(v, Mapping):
        raise TypeError(f"dict2items requires a dictionary, got {type(v).__name__}")
    return [{key_name: k, value_name: x} for k, x in v.items()]


def f_items2dict(v, key_name="key", value_name="value"):
    return {i[key_name]: i[value_name] for i in v}


def f_flatten(v, levels=None, skip_nulls=True):
    def rec(seq, lvl):
        out = []
        for x in seq:
            if x is None and skip_nulls:
                continue
            if isinstance(x, (list, tuple)) and (levels is None or lvl < levels):
                out.extend(rec(x, lvl + 1))
            else:
                out.append(x)
        return out
    return rec(v, 0)


def f_union(a, b):
    return _uniq(list(a) + list(b))


def _uniq(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def f_intersect(a, b):
    return _uniq([x for x in a if x in b])


def f_difference(a, b):
    return _uniq([x for x in a if x not in b])


def f_symmetric_difference(a, b):
    return _uniq([x for x in a if x not in b] + [x for x in b if x not in a])


def f_zip(*a):
    return [list(x) for x in zip(*a)]


def f_zip_longest(*a, fillvalue=None):
    return [list(x) for x in itertools.zip_longest(*a, fillvalue=fillvalue)]


def f_product(*a, repeat=1):
    return [list(x) for x in itertools.product(*a, repeat=repeat)]


def f_permutations(v, r=None):
    return [list(x) for x in itertools.permutations(v, r)]


def f_combinations(v, r):
    return [list(x) for x in itertools.combinations(v, r)]


def f_subelements(v, subkey, skip_missing=False):
    if isinstance(v, Mapping):
        v = list(v.values())
    out = []
    for el in v:
        cur = el
        for part in subkey.split("."):
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]
            elif skip_missing:
                cur = []
                break
            else:
                raise KeyError(f"could not find '{subkey}' key in iterated item")
        for s in cur:
            out.append([el, s])
    return out


def f_extract(item, container, morekeys=None):
    v = container[item]
    if morekeys is not None:
        if not isinstance(morekeys, list):
            morekeys = [morekeys]
        for k in morekeys:
            v = v[k]
    return v


def f_mandatory(v, msg=None):
    if isinstance(v, Undefined):
        name = getattr(v, "_sym", "?")
        v._use() if isinstance(v, SymUndefined) else None
        raise ValueError(msg or f"Mandatory variable '{name}' not defined.")
    return v


def f_type_debug(v):
    return type(v).__name__


def f_basename(v):
    return posixpath.basename(str(v))


def f_dirname(v):
    return posixpath.dirname(str(v))


def f_win_basename(v):
    return ntpath.basename(str(v))


def f_win_dirname(v):
    return ntpath.dirname(str(v))


def f_splitext(v):
    return list(posixpath.splitext(str(v)))


def f_expanduser(v):
    s = str(v)
    return Runtime(f"expanduser({s})") if s.startswith("~") else s


def f_realpath(v):
    return Runtime(f"realpath({v})")


def f_relpath(v, start=None):
    return posixpath.relpath(str(v), start) if start else posixpath.relpath(str(v))


def f_path_join(v):
    if isinstance(v, str):
        return v
    return posixpath.join(*[str(x) for x in v])


def f_split(v, sep=None, maxsplit=-1):
    return str(v).split(sep, maxsplit)


def f_comment(v, style="plain", decoration=None, **kw):
    dec = decoration if decoration is not None else {"plain": "# ", "c": "// ", "cblock": " * ", "erlang": "% ", "xml": "  - "}.get(style, "# ")
    lines = [dec + line if line else dec.rstrip() for line in str(v).splitlines()]
    body = "\n".join(lines)
    if style == "plain":
        return f"#\n{body}\n#"
    if style == "cblock":
        return f"/*\n{body}\n */"
    if style == "xml":
        return f"<!--\n{body}\n-->"
    return body


def f_to_uuid(v, namespace="361E6D51-FAEC-444A-9079-341386DA8E2E"):
    return str(uuid.uuid5(uuid.UUID(namespace), str(v)))


def f_strftime(fmt, second=None, utc=False):
    if second is None:
        return Runtime(f"strftime({fmt})")
    tz = datetime.timezone.utc if utc else None
    return datetime.datetime.fromtimestamp(float(second), tz).strftime(fmt)


def f_to_datetime(v, fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.strptime(str(v), fmt)


def f_log(v, base=math.e):
    return math.log(v, base)


def f_pow(v, y):
    return math.pow(v, y)


def f_root(v, base=2):
    return math.sqrt(v) if base == 2 else math.pow(v, 1.0 / base)


_UNITS = "BKMGTPEZY"


def f_human_readable(v, isbits=False, unit=None):
    n = float(v)
    i = 0
    while n >= 1024 and i < len(_UNITS) - 1:
        n /= 1024
        i += 1
    suf = _UNITS[i]
    return f"{n:.2f} {suf}{'b' if isbits else ('B' if suf != 'B' else '')}".replace(" BB", " B")


def f_human_to_bytes(v, default_unit=None, isbits=False):
    m = re.match(r"^\s*([\d.]+)\s*([A-Za-z]*)\s*$", str(v))
    if not m:
        raise ValueError(f"human_to_bytes() can't interpret {v!r}")
    num, unit = float(m.group(1)), (m.group(2) or default_unit or "B")
    i = _UNITS.find(unit[0].upper())
    if i < 0:
        raise ValueError(f"unknown unit {unit}")
    return int(num * (1024 ** i))


def f_random(v, start=None, step=None, seed=None):
    return Runtime("random()")


def f_shuffle(v, seed=None):
    return Runtime("shuffle()")


def f_urlsplit(v, query=""):
    p = urlsplit(str(v))
    d = {"scheme": p.scheme, "netloc": p.netloc, "path": p.path, "query": p.query,
         "fragment": p.fragment, "username": p.username, "password": p.password,
         "hostname": p.hostname, "port": p.port}
    return d[query] if query else d


def f_json_query(v, expr):
    try:
        import jmespath  # noqa: PLC0415
    except ImportError:
        return Runtime(f"json_query({expr!r}) [jmespath not loaded]")
    return jmespath.search(expr, _plain(v))


def f_ipaddr(v, query=""):
    try:
        if "/" in str(v):
            iface = ipaddress.ip_interface(str(v))
        else:
            iface = ipaddress.ip_interface(str(v) + ("/32" if ":" not in str(v) else "/128"))
    except ValueError:
        return False
    q = query or ""
    if q == "":
        return str(v)
    if q == "address":
        return str(iface.ip)
    if q == "network":
        return str(iface.network.network_address)
    if q == "netmask":
        return str(iface.network.netmask)
    if q == "prefix":
        return iface.network.prefixlen
    if q == "broadcast":
        return str(iface.network.broadcast_address)
    if q in ("net", "subnet", "cidr"):
        return str(iface.network)
    if q == "private":
        return str(v) if iface.ip.is_private else False
    if q == "public":
        return str(v) if not iface.ip.is_private else False
    return Runtime(f"ipaddr({q})")


def f_vault(v, *a, **kw):
    return Runtime("vault()")


def f_unvault(v, *a, **kw):
    return Runtime("unvault()")


FILTERS = {
    "bool": f_bool, "to_json": f_to_json, "to_nice_json": f_to_nice_json, "from_json": f_from_json,
    "to_yaml": f_to_yaml, "to_nice_yaml": f_to_nice_yaml, "from_yaml": f_from_yaml,
    "from_yaml_all": f_from_yaml_all, "regex_replace": f_regex_replace, "regex_search": f_regex_search,
    "regex_findall": f_regex_findall, "regex_escape": f_regex_escape, "b64encode": f_b64encode,
    "b64decode": f_b64decode, "hash": f_hash, "checksum": f_checksum, "md5": f_md5, "sha1": f_checksum,
    "password_hash": f_password_hash, "quote": f_quote, "ternary": f_ternary, "combine": f_combine,
    "dict2items": f_dict2items, "items2dict": f_items2dict, "flatten": f_flatten, "union": f_union,
    "intersect": f_intersect, "difference": f_difference, "symmetric_difference": f_symmetric_difference,
    "zip": f_zip, "zip_longest": f_zip_longest, "product": f_product, "permutations": f_permutations,
    "combinations": f_combinations, "subelements": f_subelements, "extract": f_extract,
    "mandatory": f_mandatory, "type_debug": f_type_debug, "basename": f_basename, "dirname": f_dirname,
    "win_basename": f_win_basename, "win_dirname": f_win_dirname, "splitext": f_splitext,
    "expanduser": f_expanduser, "realpath": f_realpath, "relpath": f_relpath, "path_join": f_path_join,
    "split": f_split, "comment": f_comment, "to_uuid": f_to_uuid, "strftime": f_strftime,
    "to_datetime": f_to_datetime, "log": f_log, "pow": f_pow, "root": f_root,
    "human_readable": f_human_readable, "human_to_bytes": f_human_to_bytes, "random": f_random,
    "shuffle": f_shuffle, "urlsplit": f_urlsplit, "json_query": f_json_query, "ipaddr": f_ipaddr,
    "ipv4": f_ipaddr, "ipv6": f_ipaddr, "vault": f_vault, "unvault": f_unvault,
}

# collection namespaces where these filters live, so FQCN spelling works too
FILTER_NAMESPACES = {
    "json_query": "community.general", "ipaddr": "ansible.utils", "ipv4": "ansible.utils",
    "ipv6": "ansible.utils",
}

# --------------------------------------------------------------------------- tests


def _ver_key(v):
    parts = re.split(r"[.\-+_~]", str(v))
    out = []
    for p in parts:
        for chunk in re.findall(r"\d+|[A-Za-z]+", p):
            out.append((0, int(chunk), "") if chunk.isdigit() else (1, 0, chunk))
    return out


def t_version(value, version, operator="eq", strict=None, version_type=None):
    a, b = _ver_key(value), _ver_key(version)
    ops = {
        "<": a < b, "lt": a < b, "<=": a <= b, "le": a <= b, ">": a > b, "gt": a > b,
        ">=": a >= b, "ge": a >= b, "==": a == b, "=": a == b, "eq": a == b,
        "!=": a != b, "<>": a != b, "ne": a != b,
    }
    if operator not in ops:
        raise ValueError(f"invalid version operator {operator!r}")
    return ops[operator]


def t_match(v, pattern, ignorecase=False, multiline=False):
    return re.match(pattern, str(v), _flags(ignorecase, multiline)) is not None


def t_search(v, pattern, ignorecase=False, multiline=False):
    return re.search(pattern, str(v), _flags(ignorecase, multiline)) is not None


def t_regex(v, pattern, ignorecase=False, multiline=False, match_type="search"):
    return (t_match if match_type == "match" else t_search)(v, pattern, ignorecase, multiline)


def t_subset(a, b):
    return all(x in b for x in a)


def t_superset(a, b):
    return all(x in a for x in b)


def t_contains(seq, item):
    return item in seq


def t_any(seq):
    return any(seq)


def t_all(seq):
    return all(seq)


def t_truthy(v, convert_bool=False):
    return to_bool(v) if convert_bool else bool(v)


def t_falsy(v, convert_bool=False):
    return not t_truthy(v, convert_bool)


def _res(key, default=False):
    def t(result):
        if not isinstance(result, Mapping):
            raise TypeError(f"the '{key}' test expects a dictionary (registered result)")
        return bool(result.get(key, default))
    return t


def t_failed(r):
    return _res("failed")(r)


def t_succeeded(r):
    return not t_failed(r)


def t_finished(r):
    return bool(r.get("finished", 1)) if isinstance(r, Mapping) else _res("finished")(r)


def t_fs(name):
    def t(path, *a):
        return Runtime(f"{name}({path})")
    return t


def t_vault_encrypted(v):
    from .values import Vaulted  # noqa: PLC0415
    return isinstance(v, Vaulted) or str(v).startswith("$ANSIBLE_VAULT")


def t_nan(v):
    return isinstance(v, float) and math.isnan(v)


TESTS = {
    "version": t_version, "version_compare": t_version, "match": t_match, "search": t_search,
    "regex": t_regex, "subset": t_subset, "issubset": t_subset, "superset": t_superset,
    "issuperset": t_superset, "contains": t_contains, "any": t_any, "all": t_all,
    "truthy": t_truthy, "falsy": t_falsy, "failed": t_failed, "failure": t_failed,
    "succeeded": t_succeeded, "success": t_succeeded, "successful": t_succeeded,
    "changed": _res("changed"), "change": _res("changed"), "skipped": _res("skipped"),
    "skip": _res("skipped"), "unreachable": _res("unreachable"),
    "reachable": lambda r: not _res("unreachable")(r), "finished": t_finished,
    "started": _res("started", True), "file": t_fs("file"), "directory": t_fs("directory"),
    "exists": t_fs("exists"), "link": t_fs("link"), "mount": t_fs("mount"), "abs": posixpath.isabs,
    "same_file": t_fs("same_file"), "vault_encrypted": t_vault_encrypted, "nan": t_nan,
    "isnan": t_nan,
}

# Not wrapped: these must see Runtime / Undefined as they are.
PASSTHROUGH = {"default", "d", "mandatory", "type_debug", "defined", "undefined", "none", "string"}


def _ensure_seq(v):
    return isinstance(v, Sequence) and not isinstance(v, str)


__all__ = ["FILTERS", "TESTS", "PASSTHROUGH", "FILTER_NAMESPACES", "to_bool", "f_to_json", "_ensure_seq"]
