from __future__ import annotations

from jinja2 import Template

from entra_hygiene.models import ScanResult, Severity

SEVERITY_ORDER = list(Severity)

# Pre-compiled Tailwind CSS. Regenerate with: python scripts/build_css.py
TAILWIND_CSS = """*,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }::backdrop{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x: ;--tw-pan-y: ;--tw-pinch-zoom: ;--tw-scroll-snap-strictness:proximity;--tw-gradient-from-position: ;--tw-gradient-via-position: ;--tw-gradient-to-position: ;--tw-ordinal: ;--tw-slashed-zero: ;--tw-numeric-figure: ;--tw-numeric-spacing: ;--tw-numeric-fraction: ;--tw-ring-inset: ;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur: ;--tw-brightness: ;--tw-contrast: ;--tw-grayscale: ;--tw-hue-rotate: ;--tw-invert: ;--tw-saturate: ;--tw-sepia: ;--tw-drop-shadow: ;--tw-backdrop-blur: ;--tw-backdrop-brightness: ;--tw-backdrop-contrast: ;--tw-backdrop-grayscale: ;--tw-backdrop-hue-rotate: ;--tw-backdrop-invert: ;--tw-backdrop-opacity: ;--tw-backdrop-saturate: ;--tw-backdrop-sepia: ;--tw-contain-size: ;--tw-contain-layout: ;--tw-contain-paint: ;--tw-contain-style: }/*! tailwindcss v3.4.19 | MIT License | https://tailwindcss.com*/*,:after,:before{box-sizing:border-box;border:0 solid #e5e7eb}:after,:before{--tw-content:""}:host,html{line-height:1.5;-webkit-text-size-adjust:100%;-moz-tab-size:4;-o-tab-size:4;tab-size:4;font-family:ui-sans-serif,system-ui,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;font-feature-settings:normal;font-variation-settings:normal;-webkit-tap-highlight-color:transparent}body{margin:0;line-height:inherit}hr{height:0;color:inherit;border-top-width:1px}abbr:where([title]){-webkit-text-decoration:underline dotted;text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,pre,samp{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-feature-settings:normal;font-variation-settings:normal;font-size:1em}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}table{text-indent:0;border-color:inherit;border-collapse:collapse}button,input,optgroup,select,textarea{font-family:inherit;font-feature-settings:inherit;font-variation-settings:inherit;font-size:100%;font-weight:inherit;line-height:inherit;letter-spacing:inherit;color:inherit;margin:0;padding:0}button,select{text-transform:none}button,input:where([type=button]),input:where([type=reset]),input:where([type=submit]){-webkit-appearance:button;background-color:transparent;background-image:none}:-moz-focusring{outline:auto}:-moz-ui-invalid{box-shadow:none}progress{vertical-align:baseline}::-webkit-inner-spin-button,::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}summary{display:list-item}blockquote,dd,dl,figure,h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}fieldset{margin:0}fieldset,legend{padding:0}menu,ol,ul{list-style:none;margin:0;padding:0}dialog{padding:0}textarea{resize:vertical}input::-moz-placeholder,textarea::-moz-placeholder{opacity:1;color:#9ca3af}input::placeholder,textarea::placeholder{opacity:1;color:#9ca3af}[role=button],button{cursor:pointer}:disabled{cursor:default}audio,canvas,embed,iframe,img,object,svg,video{display:block;vertical-align:middle}img,video{max-width:100%;height:auto}[hidden]:where(:not([hidden=until-found])){display:none}.mx-auto{margin-left:auto;margin-right:auto}.mb-10{margin-bottom:2.5rem}.mb-2{margin-bottom:.5rem}.mb-3{margin-bottom:.75rem}.mb-8{margin-bottom:2rem}.mt-1{margin-top:.25rem}.mt-12{margin-top:3rem}.mt-3{margin-top:.75rem}.flex{display:flex}.inline-flex{display:inline-flex}.table{display:table}.grid{display:grid}.w-24{width:6rem}.w-28{width:7rem}.w-36{width:9rem}.w-56{width:14rem}.w-full{width:100%}.max-w-screen-xl{max-width:1280px}.grid-cols-5{grid-template-columns:repeat(5,minmax(0,1fr))}.flex-wrap{flex-wrap:wrap}.items-center{align-items:center}.gap-3{gap:.75rem}.gap-x-8{-moz-column-gap:2rem;column-gap:2rem}.gap-y-1{row-gap:.25rem}.overflow-hidden{overflow:hidden}.rounded{border-radius:.25rem}.rounded-md{border-radius:.375rem}.border{border-width:1px}.border-b{border-bottom-width:1px}.border-t{border-top-width:1px}.border-red-900{--tw-border-opacity:1;border-color:rgb(127 29 29/var(--tw-border-opacity,1))}.border-red-900\/50{border-color:rgba(127,29,29,.5)}.border-zinc-800{--tw-border-opacity:1;border-color:rgb(39 39 42/var(--tw-border-opacity,1))}.bg-orange-950{--tw-bg-opacity:1;background-color:rgb(67 20 7/var(--tw-bg-opacity,1))}.bg-red-950{--tw-bg-opacity:1;background-color:rgb(69 10 10/var(--tw-bg-opacity,1))}.bg-red-950\/30{background-color:rgba(69,10,10,.3)}.bg-sky-950{--tw-bg-opacity:1;background-color:rgb(8 47 73/var(--tw-bg-opacity,1))}.bg-yellow-950{--tw-bg-opacity:1;background-color:rgb(66 32 6/var(--tw-bg-opacity,1))}.bg-zinc-800{--tw-bg-opacity:1;background-color:rgb(39 39 42/var(--tw-bg-opacity,1))}.bg-zinc-900{--tw-bg-opacity:1;background-color:rgb(24 24 27/var(--tw-bg-opacity,1))}.bg-zinc-950{--tw-bg-opacity:1;background-color:rgb(9 9 11/var(--tw-bg-opacity,1))}.px-2{padding-left:.5rem;padding-right:.5rem}.px-4{padding-left:1rem;padding-right:1rem}.px-6{padding-left:1.5rem;padding-right:1.5rem}.px-8{padding-left:2rem;padding-right:2rem}.py-0\.5{padding-top:.125rem;padding-bottom:.125rem}.py-12{padding-top:3rem;padding-bottom:3rem}.py-2\.5{padding-top:.625rem;padding-bottom:.625rem}.py-3{padding-top:.75rem;padding-bottom:.75rem}.pb-6{padding-bottom:1.5rem}.text-left{text-align:left}.text-center{text-align:center}.font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}.text-2xl{font-size:1.5rem;line-height:2rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.text-xs{font-size:.75rem;line-height:1rem}.font-bold{font-weight:700}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.tabular-nums{--tw-numeric-spacing:tabular-nums;font-variant-numeric:var(--tw-ordinal) var(--tw-slashed-zero) var(--tw-numeric-figure) var(--tw-numeric-spacing) var(--tw-numeric-fraction)}.leading-relaxed{line-height:1.625}.tracking-tight{letter-spacing:-.025em}.tracking-wide{letter-spacing:.025em}.tracking-wider{letter-spacing:.05em}.tracking-widest{letter-spacing:.1em}.text-green-400{--tw-text-opacity:1;color:rgb(74 222 128/var(--tw-text-opacity,1))}.text-orange-400{--tw-text-opacity:1;color:rgb(251 146 60/var(--tw-text-opacity,1))}.text-red-300{--tw-text-opacity:1;color:rgb(252 165 165/var(--tw-text-opacity,1))}.text-red-400{--tw-text-opacity:1;color:rgb(248 113 113/var(--tw-text-opacity,1))}.text-sky-400{--tw-text-opacity:1;color:rgb(56 189 248/var(--tw-text-opacity,1))}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.text-yellow-300{--tw-text-opacity:1;color:rgb(253 224 71/var(--tw-text-opacity,1))}.text-zinc-200{--tw-text-opacity:1;color:rgb(228 228 231/var(--tw-text-opacity,1))}.text-zinc-300{--tw-text-opacity:1;color:rgb(212 212 216/var(--tw-text-opacity,1))}.text-zinc-400{--tw-text-opacity:1;color:rgb(161 161 170/var(--tw-text-opacity,1))}.text-zinc-500{--tw-text-opacity:1;color:rgb(113 113 122/var(--tw-text-opacity,1))}.text-zinc-600{--tw-text-opacity:1;color:rgb(82 82 91/var(--tw-text-opacity,1))}.text-zinc-700{--tw-text-opacity:1;color:rgb(63 63 70/var(--tw-text-opacity,1))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.ring-1{--tw-ring-offset-shadow:var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);--tw-ring-shadow:var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);box-shadow:var(--tw-ring-offset-shadow),var(--tw-ring-shadow),var(--tw-shadow,0 0 #0000)}.ring-orange-800{--tw-ring-opacity:1;--tw-ring-color:rgb(154 52 18/var(--tw-ring-opacity,1))}.ring-red-800{--tw-ring-opacity:1;--tw-ring-color:rgb(153 27 27/var(--tw-ring-opacity,1))}.ring-sky-800{--tw-ring-opacity:1;--tw-ring-color:rgb(7 89 133/var(--tw-ring-opacity,1))}.ring-yellow-800{--tw-ring-opacity:1;--tw-ring-color:rgb(133 77 14/var(--tw-ring-opacity,1))}.ring-zinc-700{--tw-ring-opacity:1;--tw-ring-color:rgb(63 63 70/var(--tw-ring-opacity,1))}.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.transition-colors{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.duration-75{transition-duration:75ms}.hover\:bg-zinc-800\/40:hover{background-color:rgba(39,39,42,.4)}"""

TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Hygiene \u2014 {{ result.tenant_id }}</title>
<style>{{ css }}</style>
</head>
<body class="bg-zinc-950 text-zinc-200 antialiased">

{% set sev_badge = {
  'critical': 'bg-red-950 text-red-400 ring-red-800',
  'high':     'bg-orange-950 text-orange-400 ring-orange-800',
  'medium':   'bg-yellow-950 text-yellow-300 ring-yellow-800',
  'low':      'bg-sky-950 text-sky-400 ring-sky-800',
  'info':     'bg-zinc-800 text-zinc-400 ring-zinc-700',
} %}

{% set sev_num = {
  'critical': 'text-red-400',
  'high':     'text-orange-400',
  'medium':   'text-yellow-300',
  'low':      'text-sky-400',
  'info':     'text-zinc-500',
} %}

<div class="max-w-screen-xl mx-auto px-8 py-12">

  <div class="mb-10 pb-6 border-b border-zinc-800">
    <p class="text-xs font-mono text-zinc-600 uppercase tracking-widest mb-2">entra-hygiene</p>
    <h1 class="text-xl font-semibold text-white tracking-tight">Scan Report</h1>
    <div class="flex flex-wrap gap-x-8 gap-y-1 mt-3 text-sm text-zinc-500">
      <span>Tenant <code class="text-zinc-300 font-mono text-xs">{{ result.tenant_id }}</code></span>
      <span>{{ result.started_at.strftime('%Y-%m-%d %H:%M UTC') }}</span>
      <span>{{ '%.1f'|format(result.duration_seconds) }}s</span>
      <span>{{ result.checks_ran|length }} checks ran</span>
      {% if result.errors %}<span class="text-red-400">{{ result.errors|length }} check errors</span>{% endif %}
    </div>
  </div>

  <div class="grid grid-cols-5 gap-3 mb-10">
  {% for sev in severities %}
    <div class="bg-zinc-900 border border-zinc-800 rounded-md px-4 py-3">
      <div class="text-2xl font-bold tabular-nums {{ sev_num[sev.value] }}">{{ counts[sev] }}</div>
      <div class="text-xs uppercase tracking-widest text-zinc-600 mt-1">{{ sev.value }}</div>
    </div>
  {% endfor %}
  </div>

  {% if result.errors %}
  <div class="mb-8">
    <h2 class="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">Check Errors</h2>
    <div class="rounded-md border border-red-900 overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-red-950/30 border-b border-red-900/50">
            <th class="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wider w-36">Check</th>
            <th class="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wider">Error</th>
          </tr>
        </thead>
        <tbody>
        {% for err in result.errors %}
          <tr class="border-t border-zinc-800">
            <td class="px-4 py-2.5 font-mono text-xs text-zinc-400">{{ err.check_id }}</td>
            <td class="px-4 py-2.5 text-red-300">{{ err.error }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  {% if not result.findings %}
  <div class="border border-zinc-800 rounded-md px-6 py-12 text-center">
    <p class="text-sm text-green-400 font-medium">No findings \u2014 tenant looks clean.</p>
  </div>
  {% else %}
  <div>
    <h2 class="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">Findings</h2>
    <div class="rounded-md border border-zinc-800 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900 border-b border-zinc-800">
          <tr>
            <th class="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider w-28">Severity</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider w-24">Check</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider">Title</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider">Detail</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider w-56">Remediation</th>
          </tr>
        </thead>
        <tbody>
        {% for f in findings %}
          <tr class="border-t border-zinc-800 hover:bg-zinc-800/40 transition-colors duration-75">
            <td class="px-4 py-3">
              <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ring-1 {{ sev_badge[f.severity.value] }}">{{ f.severity.value }}</span>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-zinc-500">{{ f.check_id }}</td>
            <td class="px-4 py-3 text-zinc-200 font-medium">{{ f.title }}</td>
            <td class="px-4 py-3 text-zinc-400 leading-relaxed">{{ f.detail }}</td>
            <td class="px-4 py-3 text-zinc-400 leading-relaxed">{{ f.remediation }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <p class="mt-12 text-center text-xs text-zinc-700">Generated by entra-hygiene</p>

</div>
</body>
</html>
""")


def render_html(result: ScanResult) -> str:
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity),
    )
    return TEMPLATE.render(
        result=result,
        severities=SEVERITY_ORDER,
        counts=result.counts_by_severity,
        findings=sorted_findings,
        css=TAILWIND_CSS,
    )
