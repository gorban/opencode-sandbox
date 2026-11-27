// Checks the token pairings the system relies on, in both modes, against WCAG 2.2 AA.
// Run: node build/contrast.mjs
import { LIGHT, DARK, toLinear } from './tokens.mjs';

const light = Object.fromEntries(Object.entries(LIGHT).map(([k, v]) => [`--color-${k}`, v]));
const dark = Object.fromEntries(Object.entries(DARK).map(([k, v]) => [`--color-${k}`, v]));
const lum = (s) => { const { lin } = toLinear(s); return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

const TEXT = 4.5, UI = 3;
const pairs = [
  ['ink', 'paper', TEXT], ['ink', 'paper-2', TEXT], ['ink', 'paper-3', TEXT],
  ['ink-2', 'paper', TEXT], ['ink-2', 'paper-2', TEXT], ['ink-2', 'paper-3', TEXT],
  ['muted', 'paper', TEXT], ['muted', 'paper-2', TEXT], ['muted', 'paper-3', TEXT],
  ['paper', 'ink', TEXT], ['paper', 'ink-2', TEXT],
  ['rule-2', 'paper', UI], ['rule-2', 'paper-2', UI], ['rule-2', 'paper-3', UI],
  ['focus', 'paper', UI], ['focus', 'paper-2', UI],
  ['approval-ink', 'approval', TEXT], ['approval', 'paper', TEXT], ['approval', 'approval-soft', TEXT], ['ink', 'approval-soft', TEXT],
  ['inbox', 'inbox-soft', TEXT], ['inbox', 'paper', TEXT], ['ink', 'inbox-soft', TEXT], ['ink-2', 'inbox-soft', TEXT],
  ['caution', 'paper', TEXT], ['caution', 'paper-2', TEXT], ['caution', 'caution-soft', TEXT], ['ink', 'caution-soft', TEXT], ['ink-2', 'caution-soft', TEXT],
  ['caution-edge', 'paper', UI], ['caution-edge', 'paper-2', UI], ['caution-edge', 'caution-soft', UI],
  ['ok', 'paper', TEXT], ['ok', 'paper-2', TEXT], ['ok', 'ok-soft', TEXT], ['ink', 'ok-soft', TEXT],
  ['bad', 'paper', TEXT], ['bad', 'paper-2', TEXT], ['bad', 'bad-soft', TEXT], ['ink', 'bad-soft', TEXT],
  ['muted', 'ok-soft', TEXT], ['muted', 'bad-soft', TEXT],
  ['approval', 'paper-2', TEXT], ['inbox', 'paper-2', TEXT], ['inbox-ink', 'inbox', TEXT], ['approval', 'paper-3', TEXT],
  ['muted', 'caution-soft', TEXT], ['ink-2', 'bad-soft', TEXT], ['caution', 'caution-soft', TEXT], ['approval-ink', 'approval', TEXT], ['ink-2', 'paper-3', TEXT],
  ['approval-band-ink', 'approval-band', TEXT],
  ['bad', 'paper-3', TEXT], ['ok', 'paper-3', TEXT], ['caution', 'paper-3', TEXT], ['caution-edge', 'paper-3', UI], ['ok', 'paper-3', UI],
];
let fails = 0;
for (const [name, set] of [['light', light], ['dark', dark]]) {
  for (const [fg, bg, min] of pairs) {
    const r = ratio(set[`--color-${fg}`], set[`--color-${bg}`]);
    if (r < min) { fails++; console.log(`FAIL ${name} ${fg} on ${bg}: ${r.toFixed(2)} < ${min}`); }
  }
}
console.log(fails ? `${fails} failing pairs` : `all ${pairs.length * 2} pairings pass`);
process.exit(fails ? 1 : 0);
