import { Resvg } from '@resvg/resvg-js';
import fs from 'node:fs';
import path from 'node:path';

const OUT = process.argv[2];
fs.mkdirSync(OUT, { recursive: true });

const TAGLINE = 'MCP server for Windows security research';
const MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";

const THEMES = {
  dark: {
    bg: ['#161B22', '#0B0E13'], border: '#30363D', ink: '#F0F3F6', muted: '#8B949E',
    amber: ['#FFC53D', '#FF7A1A'], byte: '#FFFFFF', byteOp: [0.05, 0.13],
  },
  light: {
    bg: ['#FFFFFF', '#F3F5F8'], border: '#D0D7DE', ink: '#0E1116', muted: '#57606A',
    amber: ['#FFA51F', '#F0580A'], byte: '#0E1116', byteOp: [0.05, 0.12],
  },
};

const r2 = (n) => Math.round(n * 100) / 100;

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The mark: a lowercase "p" drawn as a crowbar — one stroke, hooked bowl left
// open, chisel tip on the stem, claw notch on the hook.
function crowbarP({ x0, y0, R, S, desc, stroke, id }) {
  const cy = y0 + R, base = y0 + 2 * R, B = base + desc;
  const ex = x0 + R - 0.2 * R;
  const h = S / 2;
  const d = `M${x0},${B} L${x0},${cy} A${R},${R} 0 1 1 ${x0 + R},${base} L${r2(ex)},${base}`;
  const bx = x0 - S, by = y0 - S, bw = 2 * R + 2 * S, bh = 2 * R + desc + 2 * S;
  const defs = `<mask id="${id}" maskUnits="userSpaceOnUse" x="${bx}" y="${by}" width="${bw}" height="${bh}">
      <rect x="${bx}" y="${by}" width="${bw}" height="${bh}" fill="#fff"/>
      <polygon points="${x0 - h - 1},${B + 1} ${x0 + h + 1},${B + 1} ${x0 - h - 1},${r2(B - S * 0.62)}" fill="#000"/>
      <polygon points="${r2(ex - 1)},${r2(base - S * 0.2)} ${r2(ex - 1)},${r2(base + S * 0.2)} ${r2(ex + S * 0.42)},${base}" fill="#000"/>
    </mask>`;
  const body = `<path d="${d}" fill="none" stroke="${stroke}" stroke-width="${S}" stroke-linejoin="round" mask="url(#${id})"/>`;
  return { defs, body };
}

function grad(id, [a, b], x1, y1, x2, y2) {
  return `<linearGradient id="${id}" gradientUnits="userSpaceOnUse" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"><stop offset="0" stop-color="${a}"/><stop offset="1" stop-color="${b}"/></linearGradient>`;
}

// ---------- icon ----------
function icon({ theme = 'dark', tile = true, mono = null }) {
  const t = THEMES[theme];
  const R = 96, S = 58, x0 = 160, y0 = 104, desc = 140;
  const p = crowbarP({ x0, y0, R, S, desc, stroke: mono || 'url(#amber)', id: 'cut' });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512" role="img" aria-label="pry">
  <title>pry</title>
  <defs>
    ${grad('bg', t.bg, 0, 0, 0, 512)}
    ${grad('amber', t.amber, 120, 70, 400, 440)}
    ${p.defs}
  </defs>
  ${tile ? `<rect x="0" y="0" width="512" height="512" rx="116" fill="url(#bg)"/>
  <rect x="3" y="3" width="506" height="506" rx="113" fill="none" stroke="${t.border}" stroke-width="6"/>` : ''}
  ${p.body}
</svg>
`;
}

// ---------- wordmark (local units: x-height 130 incl. stroke, stroke 30) ----------
// Squared stroke ends; the y's descender is a straight bar with the same chisel tip as the p.
const WM_RX = 165, WM_YX = 249; // r stem / y left stem centrelines
const WM = { w: WM_YX + 115, h: 200, ox: 0, oy: 0 };
function wordmark({ t, idp }) {
  const S = 30, R = 50, XH = 130, B = WM.h;
  const p = crowbarP({ x0: 15, y0: 15, R, S, desc: B - 115, stroke: `url(#${idp}g)`, id: `${idp}m` });
  const rx = WM_RX, rr = 42, yx = WM_YX;
  const st = `fill="none" stroke="${t.ink}" stroke-width="${S}"`;
  const defs = grad(`${idp}g`, t.amber, 0, 0, 130, 200) + p.defs;
  const body = `${p.body}
    <path d="M${rx},${XH} V${15 + rr} A${rr},${rr} 0 0 1 ${rx + rr},15 H${rx + rr + 16}" ${st}/>
    <path d="M${yx},0 V65 A50,50 0 0 0 ${yx + 100},65" ${st}/>
    <polygon points="${yx + 85},0 ${yx + 115},0 ${yx + 115},${B} ${yx + 85},${r2(B - S * 0.62)}" fill="${t.ink}"/>`;
  return { defs, body };
}

// ---------- hex-dump texture, pried open along a seam ----------
function hexTexture({ t, hx, hy, w, h, k, radius = 0, avoid = null, seed = 7 }) {
  const rand = rng(seed);
  const step = 17 * k, bh = 6 * k, bw = 18 * k, bg = 7 * k, gg = 12 * k;
  const angle = 3.6;
  const [o0, o1] = t.byteOp;
  const row = (y, amber, deg = 0) => {
    const a = (deg * Math.PI) / 180, ca = Math.cos(a), sa = Math.sin(a);
    let x = hx, out = '';
    const pill = (px, pw, op, fill) => {
      const f = Math.min(1, Math.max(0, (px - hx) / (210 * k)));
      const o = Math.round(op * f * f * 1000) / 1000;
      // where this pill lands after the block is rotated about the hinge
      const mx = px + pw / 2 - hx, my = y - hy;
      const X = hx + mx * ca - my * sa, Y = hy + mx * sa + my * ca;
      if (X - pw / 2 > w || Y < -bh || Y > h + bh) return '';
      if (avoid && X - pw / 2 < avoid.x2 && Y > avoid.y1 && Y < avoid.y2) return '';
      const c = radius * 1.3;
      if (c && X + pw / 2 > w - c && (Y < c || Y > h - c)) return '';
      return o < 0.004 ? '' : `<rect x="${r2(px)}" y="${r2(y - bh / 2)}" width="${r2(pw)}" height="${r2(bh)}" rx="${r2(bh / 2)}" fill="${fill}" opacity="${o}"/>`;
    };
    out += pill(x, 52 * k, amber ? 0.55 : o1, amber ? 'url(#bx)' : t.byte);
    x += 52 * k + 24 * k;
    for (let i = 0; i < 16; i++) {
      const v = rand();
      const op = amber ? 0.45 + 0.55 * v : (v < 0.18 ? o0 * 0.6 : o0 + (o1 - o0) * v);
      out += pill(x, bw, op, amber ? 'url(#bx)' : t.byte);
      x += bw + bg + (i % 4 === 3 ? gg : 0);
    }
    x += 12 * k;
    for (let i = 0; i < 16; i++) {
      const v = rand();
      out += pill(x, 6 * k, amber ? 0.4 + 0.6 * v : o0 + (o1 - o0) * v, amber ? 'url(#bx)' : t.byte);
      x += 9 * k;
    }
    return out;
  };
  const n = Math.ceil(h / step) + 4;
  let top = '', bot = '';
  for (let i = 1; i <= n; i++) { top += row(hy - i * step, false, -angle); bot += row(hy + i * step, false, angle); }
  const defs = `${grad('bx', t.amber, hx, 0, w, 0)}`;
  const body = `<g>
    <g transform="rotate(${-angle} ${hx} ${hy})">${top}</g>
    <g transform="rotate(${angle} ${hx} ${hy})">${bot}</g>
    ${row(hy, true)}
  </g>`;
  return { defs, body };
}

// ---------- banner ----------
function banner({ w, h, theme, s, k, padX, radius, tagSize }) {
  const t = THEMES[theme];
  const wm = wordmark({ t, idp: 'p' });
  const gap = 34 * k;
  const blockH = WM.h * s + gap + tagSize * 0.75;
  const top = (h - blockH) / 2;
  const wx = padX + WM.ox * s, wy = top + WM.oy * s;
  const tagY = top + WM.h * s + gap + tagSize * 0.75;
  const hx = padX + WM.w * s + 110 * k;
  const tagW = TAGLINE.length * tagSize * 0.63; // generous: covers wider system monospace fonts
  const avoid = { x2: padX + tagW + 20 * k, y1: tagY - tagSize * 1.5, y2: tagY + tagSize * 0.9 };
  const tex = hexTexture({ t, hx, hy: h / 2, w, h, k, radius, avoid });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="pry — ${TAGLINE}">
  <title>pry — ${TAGLINE}</title>
  <defs>
    ${grad('bg', t.bg, 0, 0, 0, h)}
        ${wm.defs}
    ${tex.defs}
  </defs>
  <rect width="${w}" height="${h}" rx="${radius}" fill="url(#bg)"/>
  ${tex.body}
  ${radius ? `<rect x="1" y="1" width="${w - 2}" height="${h - 2}" rx="${radius - 1}" fill="none" stroke="${t.border}" stroke-width="2"/>` : ''}
  <g transform="translate(${r2(wx)} ${r2(wy)}) scale(${s})">
    ${wm.body}
  </g>
  <text x="${r2(padX + 2)}" y="${r2(tagY)}" font-family="${MONO}" font-size="${tagSize}" letter-spacing="${r2(tagSize * 0.02)}" fill="${t.muted}">${TAGLINE}</text>
</svg>
`;
}

// ---------- 1:1 logo: wordmark over one amber "byte row" ----------
function squareLogo({ size = 1024, bg = true }) {
  const t = THEMES.dark;
  const wm = wordmark({ t, idp: 'p' });
  const s = (size * 0.6) / WM.w;
  const k = (WM.w * s) / 429;
  const gap = size * 0.07, bh = 6 * k;
  const top = (size - (WM.h * s + gap + bh)) / 2;
  const left = (size - WM.w * s) / 2;
  const rand = rng(11);
  const ry = top + WM.h * s + gap + bh / 2;
  let row = '', x = left;
  for (let i = 0; i < 16; i++) {
    row += `<rect x="${r2(x)}" y="${r2(ry - bh / 2)}" width="${r2(18 * k)}" height="${r2(bh)}" rx="${r2(bh / 2)}" fill="url(#bx)" opacity="${r2(0.4 + 0.6 * rand())}"/>`;
    x += 18 * k + 7 * k + (i % 4 === 3 ? 12 * k : 0);
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="pry">
  <title>pry</title>
  <defs>
    ${grad('bg', t.bg, 0, 0, 0, size)}
    ${grad('bx', t.amber, left, 0, left + WM.w * s, 0)}
    ${wm.defs}
  </defs>
  ${bg ? `<rect width="${size}" height="${size}" fill="url(#bg)"/>` : ''}
  <g transform="translate(${r2(left)} ${r2(top)}) scale(${r2(s)})">
    ${wm.body}
  </g>
  ${row}
</svg>
`;
}

// ---------- output ----------
const files = {
  'icon.svg': icon({ theme: 'dark' }),
  'mark.svg': icon({ theme: 'dark', tile: false }),
  'mark-white.svg': icon({ tile: false, mono: '#FFFFFF' }),
  'mark-black.svg': icon({ tile: false, mono: '#0E1116' }),
  'banner-dark.svg': banner({ w: 1280, h: 320, theme: 'dark', s: 0.8, k: 1, padX: 88, radius: 20, tagSize: 22 }),
  'logo-square.svg': squareLogo({}),
  'logo-square-transparent.svg': squareLogo({ bg: false }),
  'social-preview.svg': banner({ w: 1280, h: 640, theme: 'dark', s: 1.3, k: 1.5, padX: 110, radius: 0, tagSize: 34 }),
};
for (const [name, svg] of Object.entries(files)) fs.writeFileSync(path.join(OUT, name), svg);

function png(svg, width) {
  const r = new Resvg(svg, {
    fitTo: { mode: 'width', value: width },
    font: { loadSystemFonts: true, defaultFontFamily: 'Consolas', monospaceFamily: 'Consolas' },
  });
  return r.render().asPng();
}
const pngDir = path.join(OUT, 'png');
fs.mkdirSync(pngDir, { recursive: true });
const iconPngs = {};
for (const size of [16, 32, 48, 64, 128, 256, 512, 1024]) {
  iconPngs[size] = png(files['icon.svg'], size);
  fs.writeFileSync(path.join(pngDir, `icon-${size}.png`), iconPngs[size]);
}
fs.writeFileSync(path.join(pngDir, 'mark-512.png'), png(files['mark.svg'], 512));
fs.writeFileSync(path.join(pngDir, 'banner-dark.png'), png(files['banner-dark.svg'], 2560));
for (const sz of [512, 1024]) fs.writeFileSync(path.join(pngDir, `logo-square-${sz}.png`), png(files['logo-square.svg'], sz));
fs.writeFileSync(path.join(pngDir, 'logo-square-transparent-1024.png'), png(files['logo-square-transparent.svg'], 1024));
fs.writeFileSync(path.join(pngDir, 'social-preview.png'), png(files['social-preview.svg'], 1280));

// favicon.ico (PNG-compressed entries)
const icoSizes = [16, 32, 48, 256];
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(icoSizes.length, 4);
let offset = 6 + 16 * icoSizes.length;
const entries = [], blobs = [];
for (const sz of icoSizes) {
  const data = iconPngs[sz];
  const e = Buffer.alloc(16);
  e.writeUInt8(sz === 256 ? 0 : sz, 0); e.writeUInt8(sz === 256 ? 0 : sz, 1);
  e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6);
  e.writeUInt32LE(data.length, 8); e.writeUInt32LE(offset, 12);
  offset += data.length; entries.push(e); blobs.push(data);
}
fs.writeFileSync(path.join(OUT, 'favicon.ico'), Buffer.concat([header, ...entries, ...blobs]));
console.log('wrote', fs.readdirSync(OUT).join(', '), '|', fs.readdirSync(pngDir).join(', '));
