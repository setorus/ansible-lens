"""Run: python3 -m pytest tests  (or python3 tests/test_lens.py)"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lens  # noqa: E402


def run(files, **kw):
    inp = {"files": files, "entry": "pb.yml"}
    inp.update(kw)
    out = lens.analyze(inp)
    json.dumps(out)  # must serialise
    return out


def tasks(out, play=0, sec="tasks"):
    return out["plays"][play]["sections"][sec]


def arg(task, key, i=0):
    return next(a for a in task["iterations"][i]["args"] if a["key"] == key)


def test_lazy_and_precedence():
    out = run({"pb.yml": """
- hosts: all
  gather_facts: false
  vars: {a: "{{ b }}-x", b: play}
  tasks:
    - debug: msg="{{ a }}"
      vars: {b: task}
""", "inv.yml": "all:\n  hosts:\n    h1: {b: host}\n"}, inventory="inv.yml", extra_vars="")
    t = tasks(out)[0]
    assert arg(t, "msg")["value"] == "task-x"
    out = run({"pb.yml": "- hosts: all\n  gather_facts: no\n  vars: {b: play}\n  tasks:\n    - debug: msg={{b}}\n"},
              extra_vars="b: extra")
    assert arg(tasks(out)[0], "msg")["value"] == "extra"


def test_native_types_and_omit():
    out = run({"pb.yml": """
- hosts: localhost
  gather_facts: false
  vars: {n: 5, l: [1, 2]}
  tasks:
    - file: {path: /x, mode: "{{ m | default(omit) }}", size: "{{ n + 1 }}", lst: "{{ l }}", s: "a{{ n }}"}
"""})
    t = tasks(out)[0]
    assert arg(t, "mode")["omitted"]
    assert arg(t, "size")["value"] == 6 and arg(t, "size")["type"] == "int"
    assert arg(t, "lst")["value"] == [1, 2]
    assert arg(t, "s")["value"] == "a5"


def test_undefined_and_when():
    out = run({"pb.yml": """
- hosts: localhost
  gather_facts: false
  tasks:
    - debug: msg="{{ nope }}"
    - debug: msg=hi
      when: nope2 is defined
    - debug: msg=hi
      when: nope3 == 1
    - debug: msg="{{ nope4 | default('d') }}"
"""})
    t = tasks(out)
    assert "nope" in arg(t[0], "msg")["trace"]["undefined"]
    assert t[1]["status"] == "skipped"
    assert t[2]["status"] == "error"
    assert arg(t[3], "msg")["value"] == "d"
    msgs = [d["msg"] for d in out["diagnostics"]]
    assert any("nope'" in m for m in msgs) and not any("nope4" in m for m in msgs)


def test_runtime_register_and_facts():
    out = run({"pb.yml": """
- hosts: localhost
  tasks:
    - command: whoami
      register: r
    - debug: msg="{{ r.stdout | upper }}"
      when: r.rc == 0 and ansible_os_family == 'Debian'
    - debug: msg={{ item }}
      loop: "{{ r.stdout_lines }}"
"""})
    t = tasks(out)
    assert t[1]["status"] == "conditional"
    assert arg(t[1], "msg")["value"] == {"$rt": "r.stdout | upper"}
    assert t[2]["loop"]["runtime"] and len(t[2]["iterations"]) == 1


def test_kv_freeform_and_loops():
    out = run({"pb.yml": """
- hosts: localhost
  gather_facts: false
  vars: {d: {a: 1, b: 2}}
  tasks:
    - shell: echo "{{ 'a b' }}" > /tmp/x chdir=/tmp creates=/tmp/x
    - copy: src=a dest="/tmp/my file" mode=0644
    - debug: msg="{{ item.key }}={{ item.value }}"
      loop: "{{ d | dict2items }}"
    - debug: msg={{ item }}
      with_sequence: start=1 end=3 format=n%02d
    - debug: msg={{ item }}
      with_items: [[1, 2], 3]
    - debug: msg={{ item }}
      loop: "{{ 'notalist' }}"
"""})
    t = tasks(out)
    assert arg(t[0], "_raw_params")["value"] == 'echo "a b" > /tmp/x'
    assert arg(t[0], "chdir")["value"] == "/tmp"
    assert arg(t[1], "dest")["value"] == "/tmp/my file"
    assert [i["args"][0]["value"] for i in t[2]["iterations"]] == ["a=1", "b=2"]
    assert [i["item"] for i in t[3]["iterations"]] == ["n01", "n02", "n03"]
    assert [i["item"] for i in t[4]["iterations"]] == [1, 2, 3]
    assert any("requires a list" in d["msg"] for d in out["diagnostics"])


def test_blocks_includes_roles():
    files = {
        "pb.yml": """
- hosts: localhost
  gather_facts: false
  vars: {flag: false}
  tasks:
    - block:
        - debug: msg=in
      when: flag
    - include_tasks: inc.yml
      loop: [a, b]
    - include_role: {name: r1, tasks_from: other}
      vars: {p: 9}
    - import_tasks: inc.yml
      when: flag
""",
        "inc.yml": "- debug: msg=\"inc {{ item | default('none') }}\"\n",
        "roles/r1/tasks/other.yml": "- debug: msg=\"{{ p }} {{ rdef }} {{ role_name }}\"\n",
        "roles/r1/defaults/main.yml": "rdef: D\n",
    }
    out = run(files)
    t = tasks(out)
    assert t[0]["status"] == "skipped" and t[0]["sections"]["block"][0]["status"] == "skipped"
    inc = t[1]
    assert len(inc["iterations"]) == 2
    assert arg(inc["iterations"][1]["children"][0], "msg")["value"] == "inc b"
    role = t[2]["iterations"][0]["children"][0]
    assert arg(role["children"][0], "msg")["value"] == "9 D r1"
    imp = t[3]["iterations"][0]["children"][0]
    assert imp["status"] == "skipped"


def test_inventory_patterns_and_hostvars():
    files = {"pb.yml": """
- hosts: "web:!web2"
  gather_facts: false
  tasks:
    - debug: msg="{{ hostvars['db1'].port }} {{ groups.web | length }} {{ ansible_user }}"
""", "hosts": "[web]\nweb[1:3] ansible_user=u\n[db]\ndb1 port=5432\n[all:vars]\nx=1\n"}
    out = run(files, inventory="hosts", host="web1")
    p = out["plays"][0]
    assert p["matched"] == ["web1", "web3"]
    assert arg(p["sections"]["tasks"][0], "msg")["value"] == "5432 3 u"
    out = run(files, inventory="hosts", host="web2")
    assert not out["plays"][0]["targeted"]


def test_template_and_filters():
    files = {"pb.yml": """
- hosts: localhost
  gather_facts: false
  vars:
    users: [{n: a, admin: true}, {n: b, admin: false}]
    cfg: "{{ {'a': 1} | combine({'b': [1]}, recursive=true) }}"
  tasks:
    - template: src=t.j2 dest=/x
    - debug:
        msg: "{{ users | selectattr('admin') | map(attribute='n') | list | to_json }} {{ cfg.b }} {{ '1.10' is version('1.9', '>') }} {{ 'abc' | regex_replace('b', 'X') }} {{ lookup('file', 'f.txt') }} {{ lookup('env', 'HOME') }}"
""", "templates/t.j2": "{% for u in users %}{{ u.n }}{% if not loop.last %},{% endif %}{% endfor %}\n",
             "files/f.txt": "F\n"}
    out = run(files)
    t = tasks(out)
    assert t[0]["iterations"][0]["extra"]["template"]["output"] == "a,b"
    v = arg(t[1], "msg")["value"]
    assert v.startswith('["a"] [1] True aXc F'), v
    assert "runtime:env:HOME" in v


def test_syntax_error_and_recursion():
    out = run({"pb.yml": """
- hosts: localhost
  gather_facts: false
  vars: {a: "{{ a }}"}
  tasks:
    - debug: msg="{{ a }}"
    - debug: msg="{{ x | }}"
"""})
    t = tasks(out)
    assert any("recursive" in e for e in arg(t[0], "msg")["trace"]["errors"])
    assert any("syntax" in e for e in arg(t[1], "msg")["trace"]["errors"])


def test_handlers_and_import_playbook():
    files = {"pb.yml": "- import_playbook: other.yml\n",
             "other.yml": """
- hosts: localhost
  gather_facts: false
  tasks:
    - command: x
      notify: h1
  handlers:
    - name: h1
      command: y
    - name: h2
      command: z
"""}
    out = run(files)
    assert out["plays"][0]["kind"] == "import_playbook"
    hs = out["plays"][1]["handlers"]
    assert hs[0]["status"] == "conditional" and hs[1]["status"] == "skipped"


def test_env_lookup():
    pb = {"pb.yml": """
- hosts: localhost
  gather_facts: false
  tasks:
    - debug:
        msg: "{{ lookup('env', 'APP_HOME') }}/{{ lookup('ansible.builtin.env', 'MISSING') }}"
    - debug: {msg: "{{ query('env', 'A', 'B') }}"}
"""}
    out = run(pb)
    assert arg(tasks(out)[0], "msg")["trace"]["runtime"] == ["env:APP_HOME", "env:MISSING"]
    out = run(pb, env="# comment\nexport APP_HOME='/opt/app'\nA=1\nB=\"two words\"\n")
    m = arg(tasks(out)[0], "msg")
    assert m["value"].startswith("/opt/app/") and m["trace"]["runtime"] == ["env:MISSING"]
    assert any(r["name"] == "APP_HOME" and r["source"] == "environment" for r in m["trace"]["refs"])
    assert arg(tasks(out)[1], "msg")["value"] == ["1", "two words"]
    out = run(pb, env="APP_HOME: /srv\nA: 5\nB: true\n")
    assert arg(tasks(out)[1], "msg")["value"] == ["5", "true"]
    assert arg(tasks(out)[0], "msg")["value"].startswith("/srv/")


if __name__ == "__main__":
    fails = 0
    for k, f in list(globals().items()):
        if k.startswith("test_"):
            try:
                f()
                print("ok  ", k)
            except Exception as e:  # noqa: BLE001
                fails += 1
                import traceback
                traceback.print_exc()
                print("FAIL", k, e)
    sys.exit(1 if fails else 0)
