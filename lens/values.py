"""Symbolic values and tracing used while templating.

Nothing here executes Ansible. Two special value kinds stand in for things that
only exist at run time or do not exist at all:

* ``Runtime``      - value produced on the managed host (registered results,
                     gathered facts, env lookups...). Any operation on it gives
                     another ``Runtime`` and marks the current trace.
* ``SymUndefined`` - Jinja2 ``Undefined`` that remembers its dotted path and
                     marks the trace when it is actually *used* (printed,
                     iterated, compared, tested for truth). ``is defined`` and
                     ``| default()`` do not count as use, same as in Ansible.
"""
from contextlib import contextmanager

from jinja2 import Undefined
from jinja2.exceptions import UndefinedError
from jinja2.utils import missing

# --------------------------------------------------------------------------- trace


class Trace:
    """Collects what one template evaluation touched."""

    def __init__(self):
        self.refs = []          # dicts: name, source, depth, raw, value
        self.undefined = []     # dotted names that were used while undefined
        self.runtime = []       # runtime paths that influenced the result
        self.errors = []        # error strings
        self.depth = 0

    def add_ref(self, name, source, raw):
        ref = {"name": name, "source": source, "depth": self.depth, "raw": raw}
        self.refs.append(ref)
        return ref

    def add_undef(self, name):
        if name not in self.undefined:
            self.undefined.append(name)

    def add_runtime(self, path):
        if path not in self.runtime:
            self.runtime.append(path)

    def add_error(self, msg):
        if msg not in self.errors:
            self.errors.append(msg)

    @property
    def clean(self):
        return not (self.undefined or self.runtime or self.errors)


_STACK = []


def current():
    return _STACK[-1] if _STACK else None


@contextmanager
def tracing():
    t = Trace()
    _STACK.append(t)
    try:
        yield t
    finally:
        _STACK.pop()
        # propagate to an outer trace so nested evaluations are not lost
        outer = current()
        if outer is not None:
            for n in t.undefined:
                outer.add_undef(n)
            for n in t.runtime:
                outer.add_runtime(n)
            for e in t.errors:
                outer.add_error(e)


def _mark_rt(path):
    t = current()
    if t is not None:
        t.add_runtime(path)


def _mark_undef(name):
    t = current()
    if t is not None:
        t.add_undef(name)


# --------------------------------------------------------------------------- Runtime


def _blocked(name):
    # keep Jinja internals (jinja_pass_arg, __html__, ...) working normally
    return name.startswith("_") or name.startswith("jinja_")


class Runtime:
    """Placeholder for a value only known while the play runs."""

    __slots__ = ("_p",)

    def __init__(self, path):
        object.__setattr__(self, "_p", path)

    def _t(self):
        _mark_rt(self._p)
        return self

    def __getattr__(self, name):
        if _blocked(name):
            raise AttributeError(name)
        return Runtime(f"{self._p}.{name}")

    def __getitem__(self, key):
        if isinstance(key, Runtime):
            key._t()
            return Runtime(f"{self._p}[{key._p}]")
        if isinstance(key, str) and key.isidentifier():
            return Runtime(f"{self._p}.{key}")
        return Runtime(f"{self._p}[{key!r}]")

    def __call__(self, *a, **kw):
        return Runtime(f"{self._p}()")

    def __str__(self):
        self._t()
        return f"⟨runtime:{self._p}⟩"

    __repr__ = __str__

    def __bool__(self):
        self._t()
        return True

    def __iter__(self):
        self._t()
        return iter([Runtime(f"{self._p}[*]")])

    def __len__(self):
        self._t()
        return 1

    def __contains__(self, item):
        self._t()
        return False

    def __hash__(self):
        return hash(self._p)

    def _op(sym):
        def f(self, other=None):
            self._t()
            if isinstance(other, Runtime):
                other._t()
            o = other._p if isinstance(other, Runtime) else repr(other)
            return Runtime(f"({self._p} {sym} {o})")
        return f

    __eq__ = _op("==")
    __ne__ = _op("!=")
    __lt__ = _op("<")
    __le__ = _op("<=")
    __gt__ = _op(">")
    __ge__ = _op(">=")
    __add__ = __radd__ = _op("+")
    __sub__ = __rsub__ = _op("-")
    __mul__ = __rmul__ = _op("*")
    __truediv__ = __rtruediv__ = _op("/")
    __floordiv__ = __rfloordiv__ = _op("//")
    __mod__ = __rmod__ = _op("%")
    __pow__ = __rpow__ = _op("**")
    __neg__ = _op("neg")
    __pos__ = _op("pos")
    del _op

    def __int__(self):
        self._t()
        return 0

    def __float__(self):
        self._t()
        return 0.0


# --------------------------------------------------------------------------- Undefined


class SymUndefined(Undefined):
    """Undefined that keeps its dotted path and records real use."""

    __slots__ = ("_sym",)

    def __init__(self, hint=None, obj=missing, name=None, exc=UndefinedError, sym=None):
        super().__init__(hint, obj, name, exc)
        if sym is None:
            if obj is not missing and name is not None:
                sym = f"{_short(obj)}.{name}"
            else:
                sym = name if name is not None else "?"
        self._sym = sym

    def _use(self):
        _mark_undef(self._sym)

    def _fail_with_undefined_error(self, *args, **kwargs):
        self._use()
        raise UndefinedError(f"'{self._sym}' is undefined")

    def __getattr__(self, name):
        if _blocked(name):
            raise AttributeError(name)
        return SymUndefined(sym=f"{self._sym}.{name}")

    def __getitem__(self, key):
        return SymUndefined(sym=f"{self._sym}[{key!r}]")

    def __str__(self):
        self._use()
        return f"⟨undefined:{self._sym}⟩"

    def __repr__(self):
        return f"⟨undefined:{self._sym}⟩"

    def __iter__(self):
        self._use()
        return iter(())

    def __bool__(self):
        self._use()
        return False

    def __len__(self):
        self._use()
        return 0

    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        self._use()
        return False

    def __ne__(self, other):
        self._use()
        return True

    __add__ = __radd__ = __sub__ = __rsub__ = _fail_with_undefined_error
    __mul__ = __rmul__ = __div__ = __rdiv__ = _fail_with_undefined_error
    __truediv__ = __rtruediv__ = __floordiv__ = __rfloordiv__ = _fail_with_undefined_error
    __mod__ = __rmod__ = __pos__ = __neg__ = __call__ = _fail_with_undefined_error
    __lt__ = __le__ = __gt__ = __ge__ = __int__ = __float__ = _fail_with_undefined_error
    __complex__ = __pow__ = __rpow__ = _fail_with_undefined_error


def _short(obj):
    if isinstance(obj, Runtime):
        return obj._p
    if isinstance(obj, dict):
        return "dict"
    if isinstance(obj, (list, tuple)):
        return "list"
    return type(obj).__name__


class Unsafe(str):
    """Value tagged ``!unsafe``: never templated."""


class Vaulted(str):
    """Value tagged ``!vault``: content is not decrypted."""
