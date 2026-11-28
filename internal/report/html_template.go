package report

// htmlTemplate is the single-file report page. It loads nothing from the
// network: CSS is inline and the only script is a small optional enhancement
// (copy buttons, expanding evidence before printing). All dynamic values go
// through html/template contextual escaping.
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Gatecrasher report {{.R.ID}}</title>
<style>
:root{
  --bg:#f6f7f9;--surface:#ffffff;--surface-2:#f0f2f5;--text:#141a24;--muted:#4a5568;--border:#d5dae2;
  --accent:#1d4ed8;--focus:#1d4ed8;--code-bg:#0f1623;--code-text:#e6ebf3;--code-muted:#9fb0c8;
  --critical-bg:#fde8e8;--critical-fg:#9b1c1c;
  --high-bg:#ffedd5;--high-fg:#9a3412;
  --medium-bg:#fef3c7;--medium-fg:#854d0e;
  --low-bg:#dbeafe;--low-fg:#1e40af;
  --info-bg:#e5e7eb;--info-fg:#374151;
  --good-fg:#166534;--bad-fg:#9b1c1c;--shadow:0 1px 2px rgba(15,22,35,.06),0 4px 16px rgba(15,22,35,.05);
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0b0f17;--surface:#121926;--surface-2:#192131;--text:#e7ebf2;--muted:#a0abbd;--border:#273146;
    --accent:#8ab4ff;--focus:#8ab4ff;--code-bg:#080b12;--code-text:#e6ebf3;--code-muted:#8fa1bb;
    --critical-bg:#3b1416;--critical-fg:#ffb4b4;
    --high-bg:#3b200c;--high-fg:#ffc796;
    --medium-bg:#35290b;--medium-fg:#fcd979;
    --low-bg:#10264a;--low-fg:#a5c6ff;
    --info-bg:#1f2937;--info-fg:#cbd5e1;
    --good-fg:#86efac;--bad-fg:#ffb4b4;--shadow:none;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px;border-radius:2px}
.skip{position:absolute;left:-999px;top:8px;background:var(--surface);color:var(--text);padding:8px 12px;border:2px solid var(--focus);z-index:10}
.skip:focus{left:8px}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}
header.top{padding:20px 0 4px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.02em}
.brand .mark{width:12px;height:12px;border-radius:3px;background:var(--critical-fg)}
.brand small{font-weight:500;color:var(--muted);margin-left:auto;font-size:.85rem}
nav.sections ul{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-wrap:wrap;gap:6px 18px;font-size:.92rem}
h1,h2,h3{line-height:1.25;margin:0}
h2{font-size:1.35rem;margin:40px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
h3{font-size:1.08rem}
section{scroll-margin-top:12px}
.hero{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px 24px;margin-top:16px;box-shadow:var(--shadow)}
.hero h1{font-size:1rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.big{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin:8px 0 14px}
.big .n{font-size:clamp(3.4rem,14vw,5.5rem);font-weight:800;line-height:1;letter-spacing:-.03em}
.big .l{font-size:1.5rem;font-weight:600;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px;padding:0;list-style:none}
.chip,.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:3px 11px;font-size:.85rem;font-weight:600;white-space:nowrap}
.chip b{font-variant-numeric:tabular-nums}
.sev-critical{background:var(--critical-bg);color:var(--critical-fg)}
.sev-high{background:var(--high-bg);color:var(--high-fg)}
.sev-medium{background:var(--medium-bg);color:var(--medium-fg)}
.sev-low{background:var(--low-bg);color:var(--low-fg)}
.sev-info{background:var(--info-bg);color:var(--info-fg)}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0;font-size:.95rem}
dl.meta dt{color:var(--muted)}
dl.meta dd{margin:0;overflow-wrap:anywhere}
.scope-list{margin:0;padding-left:1.1em}
.card{background:var(--surface);border:1px solid var(--border);border-left-width:5px;border-radius:12px;padding:18px 18px 14px;margin:0 0 16px;box-shadow:var(--shadow)}
.card.critical{border-left-color:var(--critical-fg)}.card.high{border-left-color:var(--high-fg)}
.card.medium{border-left-color:var(--medium-fg)}.card.low{border-left-color:var(--low-fg)}.card.info{border-left-color:var(--info-fg)}
.card header{display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;margin-bottom:6px}
.card header h3{flex:1 1 220px}
.facts{display:flex;flex-wrap:wrap;gap:6px 14px;color:var(--muted);font-size:.88rem;margin:0 0 10px;padding:0;list-style:none}
.facts code,.card code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em}
.facts code{overflow-wrap:anywhere}
.badge{background:var(--surface-2);color:var(--text);border:1px solid var(--border);font-weight:500;font-size:.78rem;padding:1px 9px}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 12px;padding:0;list-style:none}
.status{font-weight:700;font-size:.85rem}
.status.bad{color:var(--bad-fg)}.status.good{color:var(--good-fg)}.status.unk{color:var(--muted)}
.card p{margin:0 0 10px}
.card .lbl{font-weight:600}
.codewrap{position:relative;margin:6px 0 12px}
pre{margin:0;background:var(--code-bg);color:var(--code-text);border-radius:8px;padding:12px 14px;overflow-x:auto;font:.84rem/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.copy{position:absolute;top:6px;right:6px;background:#26334a;color:#eaf0fb;border:1px solid #3b4a66;border-radius:6px;padding:3px 10px;font:600 .78rem system-ui,sans-serif;cursor:pointer}
.copy[hidden]{display:none}
.sub{font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:10px 0 2px;font-weight:700}
details{margin:8px 0;border:1px solid var(--border);border-radius:8px;background:var(--surface-2)}
details>summary{cursor:pointer;padding:8px 12px;font-weight:600;font-size:.92rem}
details>div{padding:0 12px 10px}
.fix{margin:10px 0 0;padding:10px 12px;border-radius:8px;background:var(--surface-2);font-size:.95rem}
.tablewrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:.93rem}
caption{text-align:left;padding:10px 14px;color:var(--muted);font-size:.88rem}
th,td{text-align:left;padding:10px 14px;border-top:1px solid var(--border);vertical-align:top}
thead th{border-top:0;background:var(--surface-2);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap}
td.ok{color:var(--good-fg);font-weight:600}td.no{color:var(--bad-fg);font-weight:600}td.unk{color:var(--muted);font-weight:600}
td.wrap,td code{overflow-wrap:anywhere}
.empty{color:var(--muted);padding:12px 0}
footer{margin:48px 0 32px;color:var(--muted);font-size:.85rem}
@media (max-width:480px){
  .hero{padding:20px 16px}.card{padding:14px 12px 10px}
  dl.meta{grid-template-columns:1fr}dl.meta dt{margin-top:6px}
}
@media print{
  :root{--bg:#fff}
  body{font-size:11pt}
  .skip,nav.sections,.copy{display:none!important}
  .hero,.card,.tablewrap{box-shadow:none;break-inside:avoid}
  pre{white-space:pre-wrap}
  a{color:inherit}
}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to report</a>
<header class="top"><div class="wrap">
  <div class="brand"><span class="mark" aria-hidden="true"></span>Gatecrasher<small>Security report</small></div>
  <nav class="sections" aria-label="Report sections"><ul>
    <li><a href="#summary">Summary</a></li>
    <li><a href="#findings">Findings</a></li>
    {{if .Review}}<li><a href="#review">Needs review</a></li>{{end}}
    <li><a href="#settings">Settings</a></li>
    <li><a href="#reachability">Reachability</a></li>
    {{if .BeforeAfter}}<li><a href="#before-after">Before &amp; after</a></li>{{end}}
    <li><a href="#method">Method &amp; scope</a></li>
  </ul></nav>
</div></header>
<main id="main" class="wrap">

<section id="summary" aria-labelledby="summary-h" class="hero">
  <h1 id="summary-h">Audit summary{{if .R.Project}} &middot; {{.R.Project}}{{end}}</h1>
  <p class="big"><span class="n">{{.WaysIn}}</span><span class="l">{{if eq .WaysIn 1}}way in{{else}}ways in{{end}}</span></p>
  <ul class="chips" aria-label="Findings by severity">
    {{range .Chips}}<li class="chip sev-{{.Class}}"><b>{{.Count}}</b> {{.Name}}</li>
    {{end}}
  </ul>
  <dl class="meta">
    <dt>Target</dt><dd>{{if .R.Target}}{{.R.Target}}{{else}}not specified{{end}}</dd>
    <dt>Environment</dt><dd>{{if .R.Environment}}{{.R.Environment}}{{else}}not specified{{end}}</dd>
    <dt>Scope</dt><dd>{{if .R.Scope}}<ul class="scope-list">{{range .R.Scope}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}none declared{{end}}</dd>
    <dt>AI mode</dt><dd>{{.R.AIMode}}</dd>
    <dt>Generated</dt><dd><time datetime="{{.Generated}}">{{.GeneratedHuman}}</time></dd>
  </dl>
</section>

<section id="findings" aria-labelledby="findings-h">
  <h2 id="findings-h">Findings, ranked by severity</h2>
  {{range .Findings}}
  <article class="card {{.SevClass}}" id="{{.ID}}" aria-labelledby="{{.ID}}-h">
    <header>
      <span class="chip sev-{{.SevClass}}">{{.SevName}}</span>
      <h3 id="{{.ID}}-h">{{.Headline}}</h3>
      <span class="status {{.StatusClass}}">{{.StatusWord}}</span>
    </header>
    <ul class="facts">
      <li>ID <code>{{.ID}}</code></li>
      <li>Type <code>{{.Type}}</code></li>
      <li>Subject <code>{{.Subject}}</code></li>
      {{if .Environment}}<li>Environment <code>{{.Environment}}</code></li>{{end}}
    </ul>
    {{if .Methods}}<ul class="badges" aria-label="Detected by">{{range .Methods}}<li class="badge">{{.}}</li>{{end}}</ul>{{end}}
    {{range .Paragraphs}}<p><span class="lbl">{{.Label}}.</span> {{.Text}}</p>
    {{end}}
    {{if .Repro}}
    <p class="sub">Reproduce (key shown as &lt;CLIENT_KEY&gt;)</p>
    <div class="codewrap"><pre id="{{.ID}}-repro"><code>{{.Repro}}</code></pre><button type="button" class="copy" data-copy="{{.ID}}-repro" hidden>Copy</button></div>
    {{end}}
    {{if .Evidence}}
    <details><summary>Evidence ({{len .Evidence}})</summary><div>
      {{range .Evidence}}
      <p class="sub">{{.Kind}}</p>
      {{if .Request}}<pre><code>{{.Request}}</code></pre>{{end}}
      {{if .Response}}<pre><code>{{.Response}}</code></pre>{{end}}
      {{if .Note}}<p>{{.Note}}</p>{{end}}
      {{end}}
    </div></details>
    {{end}}
    {{if .Locations}}<p class="sub">Affected code</p><ul>{{range .Locations}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
    {{if .Fix}}<p class="fix"><span class="lbl">Fix.</span> {{.Fix}}{{if .FixPlanID}} Fix plan <a href="/plans#{{.FixPlanID}}"><code>{{.FixPlanID}}</code></a>.{{end}}</p>{{end}}
  </article>
  {{else}}<p class="empty">No findings.</p>{{end}}
</section>

{{if .Review}}
<section id="review" aria-labelledby="review-h">
  <h2 id="review-h">Claude suggests reviewing ({{len .Review}})</h2>
  <p>{{.ReviewNote}}</p>
  {{range .Review}}
  <article class="card info" id="{{.ID}}" aria-labelledby="{{.ID}}-h">
    <header>
      <span class="badge">? NEEDS REVIEW</span>
      <h3 id="{{.ID}}-h">{{.Title}}</h3>
    </header>
    <ul class="facts">
      <li>ID <code>{{.ID}}</code></li>
      <li>Type <code>{{.Type}}</code></li>
      <li>Subject <code>{{.Subject}}</code></li>
    </ul>
    {{if .Reason}}<p><span class="lbl">Claude's reason.</span> {{.Reason}}</p>{{end}}
  </article>
  {{end}}
</section>
{{end}}

<section id="settings" aria-labelledby="settings-h">
  <h2 id="settings-h">Environment security settings</h2>
  {{if .Settings}}
  <div class="tablewrap" role="region" aria-label="Environment security settings" tabindex="0"><table>
    <caption>A check mark means the setting is secure; a cross means it is not.</caption>
    <thead><tr><th scope="col">Environment</th><th scope="col">Client traits</th><th scope="col">Sensitive data</th><th scope="col">Server-only flags</th><th scope="col">Client-visible flags</th></tr></thead>
    <tbody>{{range .Settings}}
      <tr><th scope="row">{{.Environment}}</th>
        <td class="{{.TraitsClass}}">{{.Traits}}</td>
        <td class="{{.HiddenClass}}">{{.Hidden}}</td>
        <td>{{.ServerOnly}}</td><td>{{.ClientVisible}}</td></tr>{{end}}
    </tbody></table></div>
  {{else}}<p class="empty">No environment settings were read.</p>{{end}}
</section>

<section id="reachability" aria-labelledby="reach-h">
  <h2 id="reach-h">Reachability map</h2>
  {{if .Reach}}
  <div class="tablewrap" role="region" aria-label="Reachability map" tabindex="0"><table>
    <caption>Flag states an outsider can reach with the public key.</caption>
    <thead><tr><th scope="col">Flag</th><th scope="col">Reachable value</th><th scope="col">Reached via</th><th scope="col">Engine-verified</th><th scope="col">Live-verified</th></tr></thead>
    <tbody>{{range .Reach}}
      <tr><th scope="row"><code>{{.Flag}}</code></th><td class="wrap">{{.Value}}</td><td class="wrap">{{.Via}}</td>
        <td class="{{.EngineClass}}">{{.Engine}}</td><td class="{{.LiveClass}}">{{.Live}}</td></tr>{{end}}
    </tbody></table></div>
  {{else}}<p class="empty">No reachable states were mapped.</p>{{end}}
</section>

{{if .BeforeAfter}}
<section id="before-after" aria-labelledby="ba-h">
  <h2 id="ba-h">Before and after</h2>
  <div class="tablewrap" role="region" aria-label="Before and after" tabindex="0"><table>
    <thead><tr><th scope="col">Finding</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">Proof</th></tr></thead>
    <tbody>{{range .BeforeAfter}}
      <tr><th scope="row">{{.Title}}<br><code>{{.ID}}</code></th><td class="{{.BeforeClass}}">{{.Before}}</td><td class="{{.AfterClass}}">{{.After}}</td><td class="wrap">{{.Proof}}</td></tr>{{end}}
    </tbody></table></div>
</section>
{{end}}

<section id="method" aria-labelledby="method-h">
  <h2 id="method-h">Method and scope</h2>
  <dl class="meta">
    <dt>Scope</dt><dd>{{if .R.Scope}}<ul class="scope-list">{{range .R.Scope}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}none declared{{end}}</dd>
    <dt>Probes sent</dt><dd>{{.R.Stats.ProbesSent}}</dd>
    <dt>Duration</dt><dd>{{.Duration}}{{if .Stages}} ({{range $i, $s := .Stages}}{{if $i}}, {{end}}{{$s}}{{end}}){{end}}</dd>
    {{if .Parity}}<dt>Engine parity</dt><dd>{{.Parity}}</dd>{{end}}
    {{if .AgreeText}}<dt>AI / heuristic agreement</dt><dd>{{.AgreeText}}</dd>{{end}}
    <dt>Evaluation engine</dt><dd>{{.EngineVersion}}</dd>
    <dt>Tool</dt><dd>{{.R.Tool}} {{.R.Version}}</dd>
    <dt>Report ID</dt><dd><code>{{.R.ID}}</code> (schema {{.R.SchemaVersion}})</dd>
    {{range .R.Notes}}<dt>Note</dt><dd>{{.}}</dd>{{end}}
  </dl>
</section>

</main>
<footer><div class="wrap">Generated by Gatecrasher. Every key and secret in this report is redacted. Read-only checks only; nothing was changed in the audited environment.</div></footer>
<script>
(function(){
  document.querySelectorAll('[data-copy]').forEach(function(b){
    b.hidden=false;
    b.addEventListener('click',function(){
      var el=document.getElementById(b.getAttribute('data-copy'));
      if(el&&navigator.clipboard){navigator.clipboard.writeText(el.textContent).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1500)})}
    });
  });
  window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true})});
})();
</script>
</body>
</html>
`
