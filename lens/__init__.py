"""ansible-lens: static Ansible playbook analyzer (no execution)."""
import json

from .walker import Analyzer

__version__ = "1.0.0"


def analyze(inp):
    """inp: {files: {path: text}, entry, inventory, host, extra_vars, facts}"""
    return Analyzer(inp).run()


def analyze_json(s):
    try:
        out = analyze(json.loads(s))
    except Exception as e:  # noqa: BLE001
        import traceback  # noqa: PLC0415
        out = {"fatal": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()}
    return json.dumps(out, ensure_ascii=False, default=str)
