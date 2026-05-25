/**
 * goSignals — Logo components for React
 *
 * Drop-in React components for the goSignals brand mark and lockup.
 * No external dependencies; renders inline SVG.
 *
 * Variants:
 *   - primary       (default — white mark, phos border, dim phos waves, black fill)
 *   - mono-phos     (all phosphor)
 *   - mono-white    (all white)
 *   - mint-accent   (mint mark, phos border)
 *   - on-light      (ink mark on white badge, sage waves, deep phos border)
 *   - on-cream      (same but cream fill)
 *   - no-border     (primary minus the border)
 *
 * Usage:
 *   import { GoSignalsBadge, GoSignalsLockup, GoSignalsMark } from "./GoSignalsLogo";
 *
 *   <GoSignalsBadge size={64} />
 *   <GoSignalsBadge size={48} variant="on-light" />
 *   <GoSignalsLockup size={48} />
 *   <GoSignalsMark size={32} color="#6BE49A" />
 */

import React from "react";

// ── Color presets ────────────────────────────────────────────
const PHOS = "#6BE49A";
const PHOS_D = "#2E7C4A";
const MINT = "#B8FFC4";
const WHITE = "#FFFFFF";
const BLACK = "#000000";
const INK = "#0A1A0E";
const PHOS_DEEP = "#0d6d36";
const SAGE = "#7DBA8C";
const CREAM = "#f6f4ef";

export const GOSIGNALS_COLORS = {
  PHOS, PHOS_D, MINT, WHITE, BLACK, INK, PHOS_DEEP, SAGE, CREAM,
};

const VARIANTS = {
  primary:      { fill: BLACK, markColor: WHITE, borderColor: PHOS,      waveColor: PHOS_D,  waveOpacity: 0.9 },
  "mono-phos":  { fill: BLACK, markColor: PHOS,  borderColor: PHOS,      waveColor: PHOS,    waveOpacity: 0.5 },
  "mono-white": { fill: BLACK, markColor: WHITE, borderColor: WHITE,     waveColor: WHITE,   waveOpacity: 0.35 },
  "mint-accent":{ fill: BLACK, markColor: MINT,  borderColor: PHOS,      waveColor: PHOS_D,  waveOpacity: 0.9 },
  "on-light":   { fill: WHITE, markColor: INK,   borderColor: PHOS_DEEP, waveColor: SAGE,    waveOpacity: 0.75, borderWidth: 1.2 },
  "on-cream":   { fill: CREAM, markColor: INK,   borderColor: PHOS_DEEP, waveColor: SAGE,    waveOpacity: 0.7,  borderWidth: 1.2 },
  "no-border":  { fill: BLACK, markColor: WHITE, borderColor: null,      waveColor: PHOS_D,  waveOpacity: 0.9 },
};

// ── Geometry helpers ─────────────────────────────────────────
function buildWavePaths({ count = 6, amp = 2.6, wavelength = 22, padX = 4, padY = 9, width = 64, height = 64, samples = 48 }) {
  const innerH = height - padY * 2;
  const step = innerH / (count - 1);
  const out = [];
  for (let i = 0; i < count; i++) {
    const y0 = padY + i * step;
    let d = "";
    for (let s = 0; s <= samples; s++) {
      const t = s / samples;
      const x = padX + t * (width - padX * 2);
      const y = y0 + Math.sin(((x - padX) / wavelength) * 2 * Math.PI) * amp;
      d += (s === 0 ? "M" : "L") + x.toFixed(2) + " " + y.toFixed(2) + " ";
    }
    out.push(d.trim());
  }
  return out;
}

// Memoize so we don't recompute on every render
let _waveCache = null;
function getWavePaths() {
  if (!_waveCache) _waveCache = buildWavePaths({});
  return _waveCache;
}

// ── Mark (routing mark, no badge) ────────────────────────────
export function GoSignalsMark({ size = 32, color = WHITE, title = "goSignals", className, style }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label={title}
      className={className}
      style={style}
      fill="none"
    >
      <title>{title}</title>
      <g stroke={color} strokeWidth="2.8" fill="none" strokeLinecap="square" strokeLinejoin="miter">
        <path d="M2 32 L24 32" />
        <path d="M24 32 L42 12 L58 12" />
        <path d="M24 32 L58 32" />
        <path d="M24 32 L42 52 L58 52" />
      </g>
      <circle cx="24" cy="32" r="3.5" fill={color} />
      <rect x="55" y="9"  width="6" height="6" fill={color} />
      <rect x="55" y="29" width="6" height="6" fill={color} />
      <rect x="55" y="49" width="6" height="6" fill={color} />
    </svg>
  );
}

// ── Badge (mark + stream field + optional border) ────────────
export function GoSignalsBadge({
  size = 64,
  variant = "primary",
  simplified = false,       // drop waves; mark on solid fill (best <28px)
  title = "goSignals",
  className,
  style,
}) {
  const v = VARIANTS[variant] || VARIANTS.primary;
  const id = React.useId();
  const waves = getWavePaths();
  const markScale = 0.62;
  const markBox = 64 * markScale;
  const markScaleF = markBox / 64;
  const markX = (64 - markBox) / 2;
  const markY = (64 - markBox) / 2;
  const outlineWidth = 5;
  const ow = outlineWidth / 2;
  const stroke = 2.8;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label={title}
      className={className}
      style={style}
    >
      <title>{title}</title>
      <defs>
        <clipPath id={`gs-clip-${id}`}>
          <rect x="0" y="0" width="64" height="64" />
        </clipPath>
      </defs>
      <rect width="64" height="64" fill={v.fill} />
      {!simplified && (
        <g
          clipPath={`url(#gs-clip-${id})`}
          stroke={v.waveColor}
          strokeWidth="1.1"
          fill="none"
          strokeLinecap="round"
          opacity={v.waveOpacity}
        >
          {waves.map((d, i) => <path key={i} d={d} />)}
        </g>
      )}
      <g transform={`translate(${markX} ${markY}) scale(${markScaleF})`}>
        {!simplified && (
          <>
            <g
              stroke={v.fill}
              strokeWidth={stroke + outlineWidth}
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M2 32 L24 32" />
              <path d="M24 32 L42 12 L58 12" />
              <path d="M24 32 L58 32" />
              <path d="M24 32 L42 52 L58 52" />
            </g>
            <circle cx="24" cy="32" r={3.5 + ow} fill={v.fill} />
            <rect x={55 - ow} y={9 - ow}  width={6 + outlineWidth} height={6 + outlineWidth} fill={v.fill} />
            <rect x={55 - ow} y={29 - ow} width={6 + outlineWidth} height={6 + outlineWidth} fill={v.fill} />
            <rect x={55 - ow} y={49 - ow} width={6 + outlineWidth} height={6 + outlineWidth} fill={v.fill} />
          </>
        )}
        <g stroke={v.markColor} strokeWidth={stroke} fill="none" strokeLinecap="square" strokeLinejoin="miter">
          <path d="M2 32 L24 32" />
          <path d="M24 32 L42 12 L58 12" />
          <path d="M24 32 L58 32" />
          <path d="M24 32 L42 52 L58 52" />
        </g>
        <circle cx="24" cy="32" r="3.5" fill={v.markColor} />
        <rect x="55" y="9"  width="6" height="6" fill={v.markColor} />
        <rect x="55" y="29" width="6" height="6" fill={v.markColor} />
        <rect x="55" y="49" width="6" height="6" fill={v.markColor} />
      </g>
      {v.borderColor && (
        <rect
          x="0.75" y="0.75"
          width="62.5" height="62.5"
          fill="none"
          stroke={v.borderColor}
          strokeWidth={v.borderWidth ?? 1.5}
        />
      )}
    </svg>
  );
}

// ── Lockup (badge + wordmark) ────────────────────────────────
export function GoSignalsLockup({
  size = 48,         // badge edge length in px (wordmark scales relative)
  variant = "primary",
  gap = 0.28,        // gap as fraction of `size`
  className,
  style,
}) {
  const v = VARIANTS[variant] || VARIANTS.primary;
  const isLight = variant === "on-light" || variant === "on-cream";
  const goColor = isLight ? "#1a1a1a" : WHITE;
  const sigColor = isLight ? PHOS_DEEP : PHOS;
  const wordSize = size * 0.94;  // font-size relative to badge edge
  const gapPx = size * gap;

  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: gapPx,
        ...style,
      }}
    >
      <GoSignalsBadge size={size} variant={variant} />
      <span
        style={{
          fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          fontSize: wordSize,
          fontWeight: 500,
          letterSpacing: "-0.01em",
          lineHeight: 1,
          whiteSpace: "nowrap",
        }}
      >
        <span style={{ color: goColor }}>go</span>
        <span style={{ color: sigColor }}>Signals</span>
      </span>
    </span>
  );
}

export default GoSignalsLockup;
