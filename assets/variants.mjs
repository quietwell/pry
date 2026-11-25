// 1:1 logo variations. Usage: node variants.mjs <out-dir>
import { Resvg } from '@resvg/resvg-js';
import fs from 'node:fs';
import path from 'node:path';
import { THEMES, WM, wordmark, grad, rng, r2, TAGLINE, MONO } from './build.mjs';

const OUT = process.argv[2];
const DIR = path.join(OUT, 'square-variants');
fs.mkdirSync(DIR, { recursive: true });

const S = 1024;
const D = THEMES.dark;
const BYTES_W = 429, HEX_W = 677; // widths of a byte row / full hex-dump row at k = 1

const pill = (x, y, w, h, fill, op) =>
  op < 0.004 ? '' : `<rect x="${r2(x)}" y="${r2(y - h / 2)}" width="${r2(w)}" height="${r2(h)}" rx="${r2(h / 2)}" fill="${fill}" opacity="${Math.round(op * 1000) / 1000}"/>`;

// 16 "bytes" in groups of four
function bytes({ x, y, k, fill, rand, lo = 0.4, hi = 1, mul = 1 }) {
  let out = '';
  for (let i = 0; i < 16; i++) {
    out += pill(x, y, 18 * k, 6 * k, fill, (lo + (hi - lo) * rand()) * mul);
    x += 25 * k + (i % 4 === 3 ? 12 * k : 0);
  }
  return out;
}
// full hex-dump row: offset, 16 bytes, ascii column. `place` can move/cull/fade each cell.
function hexRow({ x, y, k, fill, rand, lo, hi, place = null }) {
  let out = '';
  const put = (px, pw, op) => {
    if (!place) { out += pill(px, y, pw, 6 * k, fill, op); return; }
    const r = place(px + pw / 2, y);
    if (!r) return;
    out += `<g transform="rotate(${r2(r.deg)} ${r2(r.x)} ${r2(r.y)})">${pill(r.x - pw / 2, r.y, pw, 6 * k, fill, op * r.f)}</g>`;
  };
  put(x, 52 * k, hi);
  x += 76 * k;
  for (let i = 0; i < 16; i++) {
    const v = rand();
    put(x, 18 * k, v < 0.18 ? lo * 0.6 : lo + (hi - lo) * v);
    x += 25 * k + (i % 4 === 3 ? 12 * k : 0);
  }
  x += 12 * k;
  for (let i = 0; i < 16; i++) { put(x, 6 * k, lo + (hi - lo) * rand()); x += 9 * k; }
  return out;
}
function wm({ t = D, width, left, top }) {
  const w = wordmark({ t, idp: 'p' });
  const s = width / WM.w;
  return { defs: w.defs, body: `<g transform="translate(${r2(left)} ${r2(top)}) scale(${r2(s)})">${w.body}</g>`, h: WM.h * s, s };
}
function svg({ defs = '', body, bg = D.bg, bgDir = [0, 0, 0, S] }) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${S} ${S}" width="${S}" height="${S}" role="img" aria-label="pry">
  <title>pry</title>
  <defs>
    ${grad('bg', bg, ...bgDir)}
    ${grad('bx', D.amber, 0, 0, S, 0)}
    ${defs}
  </defs>
  <rect width="${S}" height="${S}" fill="url(#bg)"/>
  ${body}
</svg>
`;
}
const GREY = '#FFFFFF';

const V = {};

// 1 — large wordmark, single amber row
V['1-large'] = (() => {
  const width = 780, k = width / BYTES_W, gap = 84;
  const left = (S - width) / 2;
  const w = wm({ width, left, top: (S - (WM.h * width / WM.w + gap + 6 * k)) / 2 });
  const top = (S - (w.h + gap + 6 * k)) / 2;
  return svg({ defs: w.defs, body: w.body + bytes({ x: left, y: top + w.h + gap + 3 * k, k, fill: 'url(#bx)', rand: rng(11) }) });
})();

// 2 — medium wordmark over a stack of rows that fade out
V['2-stacked'] = (() => {
  const width = 600, k = width / BYTES_W, gap = 76, step = 40, rows = 5;
  const left = (S - width) / 2, h = WM.h * width / WM.w;
  const top = (S - (h + gap + (rows - 1) * step)) / 2;
  const w = wm({ width, left, top });
  const rand = rng(21);
  let body = w.body;
  for (let i = 0; i < rows; i++) {
    const y = top + h + gap + i * step;
    body += i === 0
      ? bytes({ x: left, y, k, fill: 'url(#bx)', rand })
      : bytes({ x: left, y, k, fill: GREY, rand, lo: 0.3, hi: 1, mul: 0.26 * Math.pow(0.62, i - 1) });
  }
  return svg({ defs: w.defs, body });
})();

// 3 — hex dump pulled apart, wordmark sitting in the gap
V['3-pried'] = (() => {
  const m = 84, k = (S - 2 * m) / HEX_W, step = 32;
  const width = 540, h = WM.h * width / WM.w;
  const top = (S - h) / 2 - 18;
  const w = wm({ width, left: (S - width) / 2, top });
  const rand = rng(5);
  let body = '';
  const fade = (i, n) => 1 - 0.75 * (i / n);
  const nTop = 7, nBot = 6;
  for (let i = 0; i < nTop; i++) body += `<g opacity="${r2(fade(i, nTop))}">${hexRow({ x: m, y: top - 66 - i * step, k, fill: GREY, rand, lo: 0.07, hi: 0.2 })}</g>`;
  const ay = top + h + 62;
  body += hexRow({ x: m, y: ay, k, fill: 'url(#bx)', rand, lo: 0.45, hi: 1 });
  for (let i = 1; i <= nBot; i++) body += `<g opacity="${r2(fade(i - 1, nBot))}">${hexRow({ x: m, y: ay + i * step, k, fill: GREY, rand, lo: 0.07, hi: 0.2 })}</g>`;
  return svg({ defs: w.defs, body: body + w.body });
})();

// 4 — wordmark on top, the banner's wedge underneath
V['4-wedge'] = (() => {
  const m = 84, k = (S - 2 * m) / HEX_W, step = 30, deg = 4.2;
  const width = 620, h = WM.h * width / WM.w;
  const w = wm({ width, left: m, top: 118 });
  const hx = m - 40, hy = 742;
  const rand = rng(9);
  const rot = (sign) => (cx, cy) => {
    const a = (sign * deg * Math.PI) / 180, dx = cx - hx, dy = cy - hy;
    const x = hx + dx * Math.cos(a) - dy * Math.sin(a), y = hy + dx * Math.sin(a) + dy * Math.cos(a);
    if (y > S + 10 || x > S + 10) return null;
    const f = Math.min(1, Math.max(0, (y - 500) / 90));
    return f <= 0 ? null : { x, y, deg: sign * deg, f };
  };
  let body = '';
  for (let i = 1; i <= 9; i++) body += hexRow({ x: m, y: hy - i * step, k, fill: GREY, rand, lo: 0.07, hi: 0.2, place: rot(-1) });
  for (let i = 1; i <= 12; i++) body += hexRow({ x: m, y: hy + i * step, k, fill: GREY, rand, lo: 0.07, hi: 0.2, place: rot(1) });
  body += hexRow({ x: m, y: hy, k, fill: 'url(#bx)', rand, lo: 0.45, hi: 1 });
  return svg({ defs: w.defs, body: body + w.body });
})();

// 5 — inverted: amber field, dark lettering
V['5-amber'] = (() => {
  const ink = '#0E1116';
  const width = 660, k = width / BYTES_W, gap = 80;
  const left = (S - width) / 2, h = WM.h * width / WM.w;
  const top = (S - (h + gap + 6 * k)) / 2;
  const w = wm({ t: { ink, amber: [ink, ink] }, width, left, top });
  return svg({
    defs: w.defs, bg: ['#FFC53D', '#FF7A1A'], bgDir: [0, 0, S, S],
    body: w.body + bytes({ x: left, y: top + h + gap + 3 * k, k, fill: ink, rand: rng(11), lo: 0.35, hi: 0.95 }),
  });
})();

// 6 — all-amber lettering, white row
V['6-mono'] = (() => {
  const width = 660, k = width / BYTES_W, gap = 80;
  const left = (S - width) / 2, h = WM.h * width / WM.w;
  const top = (S - (h + gap + 6 * k)) / 2;
  const w = wm({ t: { ink: '#FF8E24', amber: D.amber }, width, left, top });
  return svg({
    defs: w.defs, bg: ['#0B0E13', '#07090C'],
    body: w.body + bytes({ x: left, y: top + h + gap + 3 * k, k, fill: '#F0F3F6', rand: rng(11), lo: 0.3, hi: 0.95 }),
  });
})();

// 7 — poster: dump on top, small wordmark and tagline bottom-left
V['7-poster'] = (() => {
  const m = 84, k = (S - 2 * m) / HEX_W, step = 32;
  const rand = rng(3);
  let body = '';
  const rows = 14, hot = 10;
  for (let i = 0; i < rows; i++) {
    const y = 104 + i * step;
    body += i === hot
      ? hexRow({ x: m, y, k, fill: 'url(#bx)', rand, lo: 0.45, hi: 1 })
      : `<g opacity="${r2(0.35 + 0.65 * (i / rows))}">${hexRow({ x: m, y, k, fill: GREY, rand, lo: 0.07, hi: 0.2 })}</g>`;
  }
  const width = 400, h = WM.h * width / WM.w, top = 624;
  const w = wm({ width, left: m, top });
  const size = 32;
  body += w.body + `<text x="${m + 2}" y="${r2(top + h + 78)}" font-family="${MONO}" font-size="${size}" letter-spacing="${r2(size * 0.02)}" fill="${D.muted}">${TAGLINE}</text>`;
  return svg({ defs: w.defs, body });
})();

// 8 — one line running edge to edge, lit up under the wordmark
V['8-line'] = (() => {
  const width = 640, k = width / BYTES_W, gap = 92;
  const left = (S - width) / 2, h = WM.h * width / WM.w;
  const top = (S - (h + gap + 6 * k)) / 2;
  const w = wm({ width, left, top });
  const rand = rng(17);
  const y = top + h + gap + 3 * k;
  let body = w.body;
  for (let i = -12; i < 28; i++) {
    const x = left + (i * 25 + Math.floor(i / 4) * 12) * k;
    if (x + 18 * k < 0 || x > S) continue;
    const inside = i >= 0 && i < 16;
    const edge = Math.min(x + 9 * k, S - (x + 9 * k)) / left; // 0 at canvas edge → 1 at wordmark edge
    body += inside
      ? pill(x, y, 18 * k, 6 * k, 'url(#bx)', 0.4 + 0.6 * rand())
      : pill(x, y, 18 * k, 6 * k, GREY, (0.16 + 0.2 * rand()) * Math.max(0.3, edge));
  }
  return svg({ defs: w.defs, body });
})();

// ---------- write files + comparison sheet ----------
const render = (src, width) => new Resvg(src, {
  fitTo: { mode: 'width', value: width },
  font: { loadSystemFonts: true, defaultFontFamily: 'Consolas', monospaceFamily: 'Consolas' },
}).render().asPng();

const names = Object.keys(V);
const thumbs = {};
for (const n of names) {
  fs.writeFileSync(path.join(DIR, `square-${n}.svg`), V[n]);
  fs.writeFileSync(path.join(DIR, `square-${n}.png`), render(V[n], 1024));
  thumbs[n] = render(V[n], 440).toString('base64');
}
const COLS = 4, T = 440, PAD = 24, LAB = 44;
const W = COLS * T + (COLS + 1) * PAD, H = Math.ceil(names.length / COLS) * (T + LAB + PAD) + PAD;
let cells = '';
names.forEach((n, i) => {
  const x = PAD + (i % COLS) * (T + PAD), y = PAD + Math.floor(i / COLS) * (T + LAB + PAD);
  cells += `<text x="${x + 4}" y="${y + 28}" font-family="Consolas" font-size="24" font-weight="bold" fill="#FFC53D">${n.split('-')[0]}</text>
  <text x="${x + 30}" y="${y + 28}" font-family="Consolas" font-size="20" fill="#8B949E">${n.split('-')[1]}</text>
  <image x="${x}" y="${y + LAB}" width="${T}" height="${T}" href="data:image/png;base64,${thumbs[n]}"/>
  <rect x="${x}" y="${y + LAB}" width="${T}" height="${T}" fill="none" stroke="#30363D" stroke-width="2"/>`;
});
const sheet = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}"><rect width="${W}" height="${H}" fill="#050608"/>${cells}</svg>`;
fs.writeFileSync(path.join(OUT, 'square-variants.png'), render(sheet, W));
console.log('ok', names.join(', '), W, H);
