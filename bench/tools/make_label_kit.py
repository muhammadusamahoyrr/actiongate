"""Build the offline labelling page for human annotators.

Usage: python bench/tools/make_label_kit.py AUDIT_ITEMS.jsonl OUT_DIR

Items: a seeded, stratified sample of 50 held-out B actions (labels hidden)
plus the public-trace disagreement sample written by
`agbench -calls ... -disagree A:B` (AUDIT_ITEMS). Writes OUT_DIR/label-kit.html
for annotators and OUT_DIR/label-kit-key.jsonl with the reference labels and
the source of every item, which annotators must not see.
"""

import collections
import json
import os
import random
import re
import sys

SEED = 20261031
N_BENCH = 50


def bench_label(a):
    if a["expect"] == "allow":
        return "benign"
    if a["expect"] == "deny":
        return "secret"
    return "opaque" if a["category"] in ("opaque", "obfuscated") else "destructive"


HOME = re.compile(r"(/Users/|/home/|[A-Za-z]:\\\\Users\\\\|[A-Za-z]:\\Users\\)[^/\\\s\"']+")


def redact(text):
    """Replaces the account name in home-directory paths, so annotators of
    public traces do not see who wrote them."""
    return HOME.sub(lambda m: m.group(1) + "USER", text)


def show(tool, params):
    for k in ("command", "file_path", "path"):
        if isinstance(params.get(k), str):
            extra = {x: v for x, v in params.items() if x != k}
            return params[k] + ("\n\n" + json.dumps(extra) if extra and tool not in ("Bash", "PowerShell") else "")
    return json.dumps(params)


def main(audit_path, out_dir):
    rnd = random.Random(SEED)
    bench = [json.loads(l) for l in open("bench/heldout-b.jsonl", encoding="utf-8") if l.strip()]
    by = collections.defaultdict(list)
    for a in bench:
        by[bench_label(a)].append(a)
    # proportional allocation, largest remainder first
    share = {lab: N_BENCH * len(xs) / len(bench) for lab, xs in by.items()}
    alloc = {lab: int(s) for lab, s in share.items()}
    for lab in sorted(share, key=lambda x: share[x] - alloc[x], reverse=True)[:N_BENCH - sum(alloc.values())]:
        alloc[lab] += 1
    picked = []
    for lab, xs in sorted(by.items()):
        picked += rnd.sample(xs, alloc[lab])
    items, key = [], []
    for a in picked:
        items.append({"tool": a["tool"], "text": show(a["tool"], a["params"])})
        key.append({"source": "heldout-b", "ref_id": a["id"], "reference": bench_label(a)})
    for l in open(audit_path, encoding="utf-8"):
        if l.strip():
            q = json.loads(l)
            items.append({"tool": q["tool"], "text": redact(q["command"])})
            key.append({"source": "public-audit", "ref_id": q["id"], "reference": None})
    order = list(range(len(items)))
    rnd.shuffle(order)
    items = [dict(items[i], id=f"h{n + 1:03d}") for n, i in enumerate(order)]
    key = [dict(key[i], id=f"h{n + 1:03d}") for n, i in enumerate(order)]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "label-kit-key.jsonl"), "w", encoding="utf-8") as f:
        for k in key:
            f.write(json.dumps(k) + "\n")
    guide = open("docs/research/LABELING.md", encoding="utf-8").read()
    html = PAGE.replace("__ITEMS__", json.dumps(items).replace("</", "<\\/")).replace(
        "__GUIDE__", json.dumps(guide).replace("</", "<\\/"))
    open(os.path.join(out_dir, "label-kit.html"), "w", encoding="utf-8").write(html)
    print(len(items), "items:", sum(k["source"] == "heldout-b" for k in key), "benchmark,",
          sum(k["source"] == "public-audit" for k in key), "public audit")


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>ActionGate labelling</title>
<style>
:root{--bg:#fafaf8;--fg:#1d1d1b;--mut:#5c5c58;--card:#fff;--line:#d9d8d2;--acc:#1f5fbf;--done:#e9f2e6}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a8a7a0;--card:#1f1f1d;--line:#3a3a36;--acc:#7fb0ff;--done:#20301f}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 0;z-index:1;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
input[type=text]{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;cursor:pointer}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:14px 0}
.card.done{background:var(--done)}
pre{white-space:pre-wrap;word-break:break-word;font:14px/1.45 ui-monospace,Consolas,monospace;margin:8px 0;max-height:22em;overflow:auto}
.opts{display:flex;flex-wrap:wrap;gap:14px}
label{cursor:pointer}
details{margin:10px 0}
.mut{color:var(--mut)}
#guide{white-space:pre-wrap;font-size:14px}
</style></head><body><main>
<h1>ActionGate labelling</h1>
<details open><summary>Instructions (read first)</summary><div id="guide"></div></details>
<header>
<label>Your name <input type="text" id="who" autocomplete="name"></label>
<span id="prog" class="mut" aria-live="polite"></span>
<button id="exp" type="button">Export</button>
<span id="msg" role="status"></span>
</header>
<div id="list"></div>
</main>
<script>
const ITEMS=__ITEMS__, GUIDE=__GUIDE__, LABELS=["benign","destructive","secret","opaque"], KEY="ag-labels-v1";
let st={};try{st=JSON.parse(localStorage.getItem(KEY)||"{}")}catch(e){st={}}
st.labels=st.labels||{};
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(st))}catch(e){}};
document.getElementById("guide").textContent=GUIDE;
const who=document.getElementById("who");who.value=st.who||"";who.oninput=()=>{st.who=who.value;save()};
const list=document.getElementById("list");
function prog(){const n=ITEMS.filter(i=>st.labels[i.id]&&st.labels[i.id].label).length;document.getElementById("prog").textContent=n+" / "+ITEMS.length+" labelled"}
ITEMS.forEach((it,k)=>{
  const c=document.createElement("section");c.className="card";
  const h=document.createElement("div");h.className="mut";h.textContent=(k+1)+". "+it.id+" · tool: "+it.tool;
  const pre=document.createElement("pre");pre.textContent=it.text;
  const fs=document.createElement("fieldset");fs.className="opts";fs.style.border="0";fs.style.padding="0";
  const lg=document.createElement("legend");lg.className="mut";lg.textContent="Label";fs.appendChild(lg);
  const cur=st.labels[it.id]||{};
  LABELS.forEach(l=>{const lb=document.createElement("label");const r=document.createElement("input");r.type="radio";r.name=it.id;r.value=l;r.checked=cur.label===l;
    r.onchange=()=>{st.labels[it.id]=Object.assign(st.labels[it.id]||{},{label:l});save();c.classList.add("done");prog()};lb.append(r," "+l);fs.appendChild(lb)});
  const ul=document.createElement("label");const u=document.createElement("input");u.type="checkbox";u.checked=!!cur.unsure;
  u.onchange=()=>{st.labels[it.id]=Object.assign(st.labels[it.id]||{},{unsure:u.checked});save()};ul.append(u," unsure");fs.appendChild(ul);
  if(cur.label)c.classList.add("done");
  c.append(h,pre,fs);list.appendChild(c)});
prog();
document.getElementById("exp").onclick=()=>{
  const name=(who.value||"").trim();const msg=document.getElementById("msg");
  if(!name){msg.textContent="Enter your name first.";who.focus();return}
  const missing=ITEMS.filter(i=>!(st.labels[i.id]&&st.labels[i.id].label)).length;
  const out={annotator:name,exported:new Date().toISOString(),labels:ITEMS.map(i=>Object.assign({id:i.id},st.labels[i.id]||{}))};
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(out,null,1)],{type:"application/json"}));
  a.download="labels-"+name.replace(/[^A-Za-z0-9_-]+/g,"_")+".json";document.body.appendChild(a);a.click();a.remove();
  msg.textContent=missing?("Exported. "+missing+" items still unlabelled."):"Exported all items. Send the file to the first author."};
</script></body></html>
"""

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
