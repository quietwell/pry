// 1:1 logo variations, round two (bigger wordmark, tilted takes). Usage: node variants2.mjs <out-dir>
import { Resvg } from '@resvg/resvg-js';
import fs from 'node:fs';
import path from 'node:path';
import { THEMES, WM, wordmark, grad, rng, r2 } from './build.mjs';

const OUT = process.argv[2];
const DIR = path.join(OUT, 'square-variants-2');
fs.mkdirSync(DIR, { recursive: true });

const S = 1024;
const D = THEMES.dark;
const BYTES_W = 429, HEX_W = 677;
const GREY = '#FFFFFF', AMB = 'url(#bx)';

const pill = (x, y, w, h, fill, op) =>
  op < 0.004 ? '' : `<rect x="${r2(x)}" y="${r2(y - h / 2)}" width="${r2(w)}" height="${r2(h)}" rx="${r2(h / 2)}" fill="${fill}" opacity="${Math.round(op * 1000) / 1000}"/>`;

function bytes({ x, y, k, fill, rand, lo = 0.4, hi = 1, mul = 1 }) {
  let out = '';
  for (let i = 0; i < 16; i++) {
    out += pill(x, y, 18 * k, 6 * k, fill, (lo + (hi - lo) * rand()) * mul);
    x += 25 * k + (i % 4 === 3 ? 12 * k : 0);
  }
  return out;
}
function hexRow({ x, y, k, fill, rand, lo, hi, mul = 1, place = null }) {
  let out = '';
  const put = (px, pw, op) => {
    if (!place) { out += pill(px, y, pw, 6 * k, fill, op * mul); return; }
    const r = place(px + pw / 2, y, pw);
    if (!r) return;
    out += `<g transform="rotate(${r2(r.deg)} ${r2(r.x)} ${r2(r.y)})">${pill(r.x - pw / 2, r.y, pw, 6 * k, fill, op * mul * r.f)}</g>`;
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
// endless row of byte groups; `style(i, x)` → [fill, opacity]
function line({ y, k, anchor, from, to, style }) {
  let out = '';
  for (let i = -80; i < 120; i++) {
    const x = anchor + (i * 25 + Math.floor(i / 4) * 12) * k;
    if (x + 18 * k < from || x > to) continue;
    const [fill, op] = style(i, x);
    out += pill(x, y, 18 * k, 6 * k, fill, op);
  }
  return out;
}
// rotate cells about a hinge; optional vertical fade window
const hinge = (hx, hy, deg, fade = null) => (cx, cy, pw) => {
  const a = (deg * Math.PI) / 180, dx = cx - hx, dy = cy - hy;
  const x = hx + dx * Math.cos(a) - dy * Math.sin(a), y = hy + dx * Math.sin(a) + dy * Math.cos(a);
  if (y > S + 12 || y < -12 || x - pw / 2 > S) return null;
  const f = fade ? Math.min(1, Math.max(0, fade(x, y))) : 1;
  return f <= 0 ? null : { x, y, deg, f };
};
function wm({ t = D, width, left, top }) {
  const w = wordmark({ t, idp: 'p' });
  const s = width / WM.w;
  return { defs: w.defs, body: `<g transform="translate(${r2(left)} ${r2(top)}) scale(${r2(s)})">${w.body}</g>`, h: WM.h * s, s };
}
function svg({ defs = '', body }) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${S} ${S}" width="${S}" height="${S}" role="img" aria-label="pry">
  <title>pry</title>
  <defs>
    ${grad('bg', D.bg, 0, 0, 0, S)}
    ${grad('bx', D.amber, 0, 0, S, 0)}
    ${defs}
  </defs>
  <rect width="${S}" height="${S}" fill="url(#bg)"/>
  ${body}
</svg>
`;
}
const hOf = (width) => (WM.h * width) / WM.w;
const V = {};

// A — as large as the square allows, one heavy amber row
V['A-max'] = (() => {
  const width = 850, k = width / BYTES_W, gap = 92, left = (S - width) / 2, h = hOf(width);
  const top = (S - (h + gap + 6 * k)) / 2;
  const w = wm({ width, left, top });
  return svg({ defs: w.defs, body: w.body + bytes({ x: left, y: top + h + gap + 3 * k, k, fill: AMB, rand: rng(11) }) });
})();

// B — big wordmark over rows that fade out
V['B-stacked'] = (() => {
  const width = 780, k = width / BYTES_W, gap = 84, step = 48, rows = 4, left = (S - width) / 2, h = hOf(width);
  const top = (S - (h + gap + (rows - 1) * step)) / 2;
  const w = wm({ width, left, top });
  const rand = rng(21);
  let body = w.body;
  for (let i = 0; i < rows; i++) {
    const y = top + h + gap + i * step;
    body += i === 0 ? bytes({ x: left, y, k, fill: AMB, rand })
      : bytes({ x: left, y, k, fill: GREY, rand, lo: 0.3, hi: 1, mul: 0.3 * Math.pow(0.6, i - 1) });
  }
  return svg({ defs: w.defs, body });
})();

// C — hex dump pulled apart, big wordmark in the gap
V['C-pried'] = (() => {
  const m = 70, k = (S - 2 * m) / HEX_W, step = 34, width = 740, h = hOf(width);
  const top = (S - h) / 2 - 22;
  const w = wm({ width, left: (S - width) / 2, top });
  const rand = rng(5);
  let body = '';
  const n = 6, fade = (i) => 1 - 0.8 * (i / n);
  for (let i = 0; i < n; i++) body += hexRow({ x: m, y: top - 62 - i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, mul: fade(i) });
  const ay = top + h + 62;
  body += hexRow({ x: m, y: ay, k, fill: AMB, rand, lo: 0.45, hi: 1 });
  for (let i = 1; i <= n; i++) body += hexRow({ x: m, y: ay + i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, mul: fade(i - 1) });
  return svg({ defs: w.defs, body: body + w.body });
})();

// D — same idea, chunky rows bleeding off both edges
V['D-bleed'] = (() => {
  const k = 1.9, step = 46, width = 800, h = hOf(width), left = (S - width) / 2;
  const top = (S - h) / 2 - 24;
  const w = wm({ width, left, top });
  const rand = rng(8);
  const grey = (mul) => () => [GREY, (0.07 + 0.16 * rand()) * mul];
  let body = '';
  const n = 6, fade = (i) => 1 - 0.8 * (i / n);
  for (let i = 0; i < n; i++) body += line({ y: top - 70 - i * step, k, anchor: left, from: -40, to: S + 40, style: grey(fade(i)) });
  const ay = top + h + 72;
  body += line({ y: ay, k, anchor: left, from: -40, to: S + 40, style: () => [AMB, 0.45 + 0.55 * rand()] });
  for (let i = 1; i <= n; i++) body += line({ y: ay + i * step, k, anchor: left, from: -40, to: S + 40, style: grey(fade(i - 1)) });
  return svg({ defs: w.defs, body: body + w.body });
})();

// E — big wordmark on top, wedge underneath
V['E-wedge'] = (() => {
  const m = 76, k = (S - 2 * m) / HEX_W, step = 30, deg = 4.2, width = 840, h = hOf(width);
  const w = wm({ width, left: (S - width) / 2, top: 78 });
  const hx = m - 40, hy = 792, floor = 78 + h + 34;
  const rand = rng(9);
  const fade = (x, y) => (y - floor) / 60;
  let body = '';
  for (let i = 1; i <= 8; i++) body += hexRow({ x: m, y: hy - i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, place: hinge(hx, hy, -deg, fade) });
  for (let i = 1; i <= 10; i++) body += hexRow({ x: m, y: hy + i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, place: hinge(hx, hy, deg) });
  body += hexRow({ x: m, y: hy, k, fill: AMB, rand, lo: 0.45, hi: 1 });
  return svg({ defs: w.defs, body: body + w.body });
})();

// F — wedge, with the wordmark riding up on the lifted half
V['F-wedge-tilt'] = (() => {
  const m = 76, k = (S - 2 * m) / HEX_W, step = 30, deg = 5.5, width = 760, h = hOf(width);
  const hx = 40, hy = 714, nTop = 2;
  const rand = rng(9);
  const wTop = hy - nTop * step - 50 - h;
  const w = wm({ width, left: 132, top: wTop });
  let body = '';
  for (let i = 1; i <= nTop; i++) body += hexRow({ x: m, y: hy - i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, place: hinge(hx, hy, -deg) });
  for (let i = 1; i <= 12; i++) body += hexRow({ x: m, y: hy + i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, mul: 1 - 0.06 * i, place: hinge(hx, hy, deg) });
  body += hexRow({ x: m, y: hy, k, fill: AMB, rand, lo: 0.45, hi: 1 });
  body += `<g transform="rotate(${-deg} ${hx} ${hy})">${w.body}</g>`;
  return svg({ defs: w.defs, body });
})();

// G — the whole thing tilted, rows running off the canvas
V['G-tilt-all'] = (() => {
  const k = 1.9, step = 46, width = 780, h = hOf(width), left = (S - width) / 2, deg = -9;
  const top = (S - h) / 2 - 30;
  const w = wm({ width, left, top });
  const rand = rng(14);
  const grey = (mul) => () => [GREY, (0.07 + 0.16 * rand()) * mul];
  let body = '';
  const n = 7, fade = (i) => 1 - 0.75 * (i / n);
  for (let i = 0; i < n; i++) body += line({ y: top - 70 - i * step, k, anchor: left, from: -260, to: S + 260, style: grey(fade(i)) });
  const ay = top + h + 72;
  body += line({ y: ay, k, anchor: left, from: -260, to: S + 260, style: () => [AMB, 0.45 + 0.55 * rand()] });
  for (let i = 1; i <= n; i++) body += line({ y: ay + i * step, k, anchor: left, from: -260, to: S + 260, style: grey(fade(i - 1)) });
  return svg({ defs: w.defs, body: `<g transform="rotate(${deg} ${S / 2} ${S / 2})">${body}${w.body}</g>` });
})();

// H — top half (rows + wordmark) levered up off a flat base
V['H-lifted'] = (() => {
  const m = 76, k = (S - 2 * m) / HEX_W, step = 32, deg = 6.5, width = 760, h = hOf(width);
  const hx = 36, hy = 800;
  const rand = rng(6);
  const wTop = hy - 52 - h;
  const w = wm({ width, left: 128, top: wTop });
  let body = '';
  for (let i = 0; i < 7; i++) body += hexRow({ x: m, y: wTop - 56 - i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, mul: 1 - 0.1 * i, place: hinge(hx, hy, -deg) });
  body += hexRow({ x: m, y: hy, k, fill: AMB, rand, lo: 0.45, hi: 1 });
  for (let i = 1; i <= 6; i++) body += hexRow({ x: m, y: hy + i * step, k, fill: GREY, rand, lo: 0.08, hi: 0.22, mul: 1 - 0.12 * (i - 1) });
  body += `<g transform="rotate(${-deg} ${hx} ${hy})">${w.body}</g>`;
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
  const [id, ...rest] = n.split('-');
  cells += `<text x="${x + 4}" y="${y + 28}" font-family="Consolas" font-size="24" font-weight="bold" fill="#FFC53D">${id}</text>
  <text x="${x + 30}" y="${y + 28}" font-family="Consolas" font-size="20" fill="#8B949E">${rest.join(' ')}</text>
  <image x="${x}" y="${y + LAB}" width="${T}" height="${T}" href="data:image/png;base64,${thumbs[n]}"/>
  <rect x="${x}" y="${y + LAB}" width="${T}" height="${T}" fill="none" stroke="#30363D" stroke-width="2"/>`;
});
const sheet = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}"><rect width="${W}" height="${H}" fill="#050608"/>${cells}</svg>`;
fs.writeFileSync(path.join(OUT, 'square-variants-2.png'), render(sheet, W));
console.log('ok', names.join(', '));
