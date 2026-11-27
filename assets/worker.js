/* Runs the Python analyzer (lens/) inside Pyodide, off the UI thread. */
const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.29.5/full/";
const LENS_FILES = ["__init__.py", "values.py", "filters.py", "loader.py", "templar.py", "walker.py"];

importScripts(PYODIDE + "pyodide.js");

const status = (msg) => self.postMessage({ type: "status", msg });

const ready = (async () => {
  status("Loading Python runtime…");
  const py = await loadPyodide({ indexURL: PYODIDE });
  status("Loading Jinja2 and PyYAML…");
  await py.loadPackage(["jinja2", "pyyaml"]);
  const base = new URL("../lens/", self.location.href);
  const bust = new URL(self.location.href).searchParams.get("v") || "";
  py.FS.mkdirTree("/home/pyodide/lens");
  await Promise.all(
    LENS_FILES.map(async (f) => {
      const r = await fetch(new URL(f + "?v=" + bust, base));
      if (!r.ok) throw new Error(`lens/${f}: HTTP ${r.status}`);
      py.FS.writeFile("/home/pyodide/lens/" + f, await r.text());
    })
  );
  py.runPython("import sys; sys.path.insert(0, '/home/pyodide')");
  const lens = py.pyimport("lens");
  const jinja = py.runPython("import jinja2; jinja2.__version__");
  self.postMessage({ type: "ready", version: lens.__version__, jinja });
  return lens;
})();

ready.catch((e) => self.postMessage({ type: "fatal", error: String(e && e.message ? e.message : e) }));

self.onmessage = async (e) => {
  const { id, input } = e.data;
  try {
    const lens = await ready;
    const out = lens.analyze_json(JSON.stringify(input));
    self.postMessage({ type: "result", id, out });
  } catch (err) {
    self.postMessage({ type: "result", id, error: String(err && err.message ? err.message : err) });
  }
};
