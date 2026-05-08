/**
 * App.js — PA #0: Minicrypt Clique Web Explorer
 * CS8.401: Principles of Information Security
 *
 * Three-tier layout:
 *   Top bar:      Foundation selector (AES-128 / DLP)
 *   Main area:    Column 1 (Build: Foundation→A) | Column 2 (Reduce: A→B)
 *   Bottom panel: Reduction proof summary (collapsible)
 *
 * Features implemented per spec:
 *   1. React scaffold with three-tier layout
 *   2. AESFoundation and DLPFoundation modules (own implementations)
 *   3. Column 1 — Build panel: Foundation→A with step-through
 *   4. Column 2 — Reduce panel: A→B with step-through, A as black box
 *   5. Routing table: all pairs from spec table
 *   6. Live data flow: all panels update on any input change
 *   7. Bidirectional mode toggle (A→B / B→A)
 *   8. Proof summary panel (collapsible)
 *   9. Stub support: "Not implemented yet (PA#N)" for unsupported paths
 */

import React, { useState, useMemo, useCallback } from 'react';
import { AllDemos } from './Demos';
import {
  AESFoundation, DLPFoundation, ggmPRF,
  PRIMITIVES, PA_STATUS, getReductionChain
} from './foundations';

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette & shared style constants
// ─────────────────────────────────────────────────────────────────────────────
const COLORS = {
  bg:         '#0f1117',
  surface:    '#1a1d27',
  border:     '#2d3148',
  accent:     '#6c63ff',
  accentLight:'#8b84ff',
  green:      '#22d3a4',
  yellow:     '#f59e0b',
  red:        '#ef4444',
  textPrimary:'#e2e8f0',
  textMuted:  '#7c85a3',
  stepBg:     '#12141e',
};

const S = {
  app: {
    minHeight: '100vh',
    background: COLORS.bg,
    color: COLORS.textPrimary,
    fontFamily: "'Fira Code', 'Consolas', 'Courier New', monospace",
    fontSize: 14,
  },
  topBar: {
    background: '#141722',
    borderBottom: `2px solid ${COLORS.accent}`,
    padding: '16px 32px',
    display: 'flex',
    alignItems: 'center',
    gap: 24,
    flexWrap: 'wrap',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
  },
  title: {
    fontSize: 18,
    fontWeight: 700,
    color: COLORS.accentLight,
    letterSpacing: '0.05em',
  },
  columns: {
    display: 'flex',
    gap: 20,
    padding: '24px 32px',
    flex: 1,
    minHeight: 0,
  },
  column: {
    flex: 1,
    background: COLORS.surface,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 12,
    padding: 24,
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
    minWidth: 0,
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
  },
  colTitle: {
    fontSize: 13,
    fontWeight: 700,
    color: COLORS.textMuted,
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    borderBottom: `1px solid ${COLORS.border}`,
    paddingBottom: 8,
    marginBottom: 4,
  },
  label: {
    fontSize: 11,
    color: COLORS.textMuted,
    marginBottom: 3,
    display: 'block',
  },
  select: {
    width: '100%',
    background: COLORS.stepBg,
    color: COLORS.textPrimary,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 4,
    padding: '5px 8px',
    fontSize: 13,
    fontFamily: 'inherit',
    cursor: 'pointer',
  },
  input: {
    width: '100%',
    background: COLORS.stepBg,
    color: COLORS.textPrimary,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 4,
    padding: '5px 8px',
    fontSize: 12,
    fontFamily: 'inherit',
    boxSizing: 'border-box',
  },
  stepBox: {
    background: COLORS.stepBg,
    border: `1px solid ${COLORS.border}`,
    borderRadius: 6,
    padding: '8px 10px',
    marginTop: 4,
    flex: 1,
    overflowY: 'auto',
    maxHeight: 320,
  },
  stepRow: {
    display: 'flex',
    gap: 8,
    padding: '3px 0',
    borderBottom: `1px solid #1e2030`,
    alignItems: 'flex-start',
  },
  stepLabel: {
    color: COLORS.textMuted,
    minWidth: 200,
    fontSize: 11,
    flexShrink: 0,
  },
  stepValue: {
    color: COLORS.green,
    wordBreak: 'break-all',
    fontSize: 11,
    flex: 1,
  },
  outputBox: {
    background: '#0d1f15',
    border: `1px solid ${COLORS.green}`,
    borderRadius: 6,
    padding: '8px 10px',
    marginTop: 8,
  },
  outputLabel: {
    fontSize: 11,
    color: COLORS.green,
    fontWeight: 700,
    marginBottom: 3,
  },
  outputValue: {
    color: COLORS.green,
    wordBreak: 'break-all',
    fontSize: 12,
  },
  stubBox: {
    background: '#1a1510',
    border: `1px solid ${COLORS.yellow}`,
    borderRadius: 6,
    padding: '10px 12px',
    marginTop: 8,
    color: COLORS.yellow,
    fontSize: 12,
  },
  errorBox: {
    background: '#1a0d0d',
    border: `1px solid ${COLORS.red}`,
    borderRadius: 6,
    padding: '8px 10px',
    color: COLORS.red,
    fontSize: 12,
    marginTop: 4,
  },
  proofPanel: {
    background: COLORS.surface,
    borderTop: `1px solid ${COLORS.border}`,
    padding: '0 16px',
  },
  proofHeader: {
    padding: '10px 0',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: 12,
    color: COLORS.textMuted,
    userSelect: 'none',
  },
  proofContent: {
    padding: '0 0 14px 0',
  },
  reductionStep: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 10,
    padding: '6px 0',
    borderBottom: `1px solid ${COLORS.border}`,
  },
  badge: (color) => ({
    background: color + '22',
    border: `1px solid ${color}`,
    color: color,
    borderRadius: 3,
    padding: '1px 6px',
    fontSize: 10,
    whiteSpace: 'nowrap',
    fontWeight: 700,
  }),
  toggleBtn: (active) => ({
    padding: '4px 12px',
    borderRadius: 4,
    border: `1px solid ${active ? COLORS.accent : COLORS.border}`,
    background: active ? COLORS.accent + '33' : 'transparent',
    color: active ? COLORS.accentLight : COLORS.textMuted,
    cursor: 'pointer',
    fontSize: 12,
    fontFamily: 'inherit',
  }),
};

// ─────────────────────────────────────────────────────────────────────────────
// StepDisplay component
// ─────────────────────────────────────────────────────────────────────────────
function StepDisplay({ steps, output, outputLabel }) {
  if (!steps || steps.length === 0) return null;
  return (
    <>
      <div style={S.stepBox}>
        {steps.map((s, i) => (
          <div key={i} style={S.stepRow}>
            <span style={S.stepLabel}>{s.label}</span>
            <span style={S.stepValue}>{s.value}</span>
          </div>
        ))}
      </div>
      {output && (
        <div style={S.outputBox}>
          <div style={S.outputLabel}>{outputLabel || 'Output'} =</div>
          <div style={S.outputValue}>{output}</div>
        </div>
      )}
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Column 1: Build Panel (Foundation → Source Primitive A)
// ─────────────────────────────────────────────────────────────────────────────
function BuildPanel({ foundation, foundationName, sourceA, onSourceChange,
                      seedHex, onSeedChange, inputHex, onInputChange,
                      bidirectional }) {
  const result = useMemo(() => {
    if (!foundation || !sourceA || !inputHex) return null;
    try {
      switch (sourceA) {
        case 'OWF': {
          const owf = foundation.asOWF ? foundation.asOWF() : null;
          return owf ? owf.evaluate(inputHex) : null;
        }
        case 'OWP': {
          const owp = foundation.asOWP ? foundation.asOWP()
                      : foundation.asOWF ? foundation.asOWF() : null;
          return owp ? owp.evaluate(inputHex) : null;
        }
        case 'PRG': {
          const prg = foundation.asPRG ? foundation.asPRG() : null;
          return prg ? prg.evaluate(seedHex || inputHex) : null;
        }
        case 'PRF': {
          const prf = foundation.asPRF ? foundation.asPRF() : null;
          return prf ? prf.evaluate(inputHex) : null;
        }
        case 'PRP': {
          const prp = foundation.asPRP ? foundation.asPRP() : null;
          return prp ? prp.evaluate(inputHex) : null;
        }
        case 'MAC': {
          // MAC from PRF: Mac_k(m) = F_k(m) — same as PRF evaluation
          const prf = foundation.asPRF ? foundation.asPRF() : null;
          if (!prf) return null;
          const r = prf.evaluate(inputHex);
          return {
            ...r,
            steps: [
              { label: 'MAC key k', value: (seedHex || inputHex).slice(0,32) },
              { label: 'Message m', value: inputHex.slice(0, 32) },
              ...r.steps,
              { label: 'Tag t = F_k(m)', value: r.output }
            ]
          };
        }
        case 'CRHF': {
          // DLP Hash demo: show MD structure
          const owf = foundation.asOWF ? foundation.asOWF() : null;
          if (!owf) return null;
          const blocks = [inputHex.slice(0,16), inputHex.slice(16,32) || '0000000000000000'];
          const cv0 = owf.evaluate('0000000000000000').output;
          const cv1 = owf.evaluate(cv0.slice(0,16) + blocks[0].slice(0,16)).output;
          const cv2 = owf.evaluate(cv1.slice(0,16) + blocks[1].slice(0,16)).output;
          return {
            steps: [
              { label: 'IV (z0)', value: cv0.slice(0, 16) },
              { label: 'Block 1', value: blocks[0] },
              { label: 'z1 = compress(z0, M1)', value: cv1.slice(0,16) },
              { label: 'Block 2 (+ padding)', value: blocks[1] },
              { label: 'z2 = compress(z1, M2)', value: cv2.slice(0,16) },
            ],
            output: cv2.slice(0, 16)
          };
        }
        case 'HMAC': {
          const prf = foundation.asPRF ? foundation.asPRF() : null;
          if (!prf) return null;
          const k = seedHex || inputHex.slice(0, 32);
          const ipad = k.split('').map((c, i) => (parseInt(c, 16) ^ (i % 2 === 0 ? 3 : 6)).toString(16)).join('');
          const opad = k.split('').map((c, i) => (parseInt(c, 16) ^ (i % 2 === 0 ? 5 : 12)).toString(16)).join('');
          const inner_key = prf.evaluate(ipad.slice(0,32)).output;
          const inner_hash = prf.evaluate((inner_key + inputHex).slice(0, 32)).output;
          const outer_key = prf.evaluate(opad.slice(0,32)).output;
          const hmac_out = prf.evaluate((outer_key + inner_hash).slice(0, 32)).output;
          return {
            steps: [
              { label: 'k ⊕ ipad', value: ipad.slice(0,32) },
              { label: 'inner H(k⊕ipad ∥ m)', value: inner_hash },
              { label: 'k ⊕ opad', value: opad.slice(0,32) },
              { label: 'HMAC = H(k⊕opad ∥ inner)', value: hmac_out },
            ],
            output: hmac_out
          };
        }
        default:
          return null;
      }
    } catch (e) {
      return { error: e.message };
    }
  }, [foundation, sourceA, inputHex, seedHex]);

  const paInfo = PA_STATUS[sourceA];
  const displayPrimitive = bidirectional ? `${sourceA} (target)` : sourceA;

  return (
    <div style={S.column}>
      <div style={S.colTitle}>
        {bidirectional ? '⬅ Column 1 — Build Target from Foundation' : 'Column 1 — Build Source Primitive from Foundation'}
      </div>

      <div>
        <label style={S.label}>Source Primitive A</label>
        <select style={S.select} value={sourceA} onChange={e => onSourceChange(e.target.value)}>
          {PRIMITIVES.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        {paInfo && (
          <div style={{ fontSize: 10, color: COLORS.textMuted, marginTop: 3 }}>
            {paInfo.pa}: {paInfo.desc}
          </div>
        )}
      </div>

      <div>
        <label style={S.label}>Input seed / key (hex)</label>
        <input
          style={S.input}
          value={seedHex}
          onChange={e => onSeedChange(e.target.value)}
          placeholder="e.g. a3f2b1c4d5e6f708..."
        />
      </div>

      <div>
        <label style={S.label}>Input message / query (hex)</label>
        <input
          style={S.input}
          value={inputHex}
          onChange={e => onInputChange(e.target.value)}
          placeholder="e.g. deadbeefcafe0123..."
        />
      </div>

      {result?.error ? (
        <div style={S.errorBox}>Error: {result.error}</div>
      ) : result ? (
        <StepDisplay
          steps={result.steps}
          output={result.output}
          outputLabel={`${foundationName} → ${sourceA}`}
        />
      ) : (
        <div style={{ color: COLORS.textMuted, fontSize: 11, marginTop: 8 }}>
          Select a primitive and enter inputs to compute...
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Column 2: Reduce Panel (Source A → Target B)
// ─────────────────────────────────────────────────────────────────────────────
function ReducePanel({ foundation, sourceA, targetB, onTargetChange,
                       queryHex, onQueryChange, col1Output, bidirectional }) {
  const reduction = useMemo(() => getReductionChain(
    bidirectional ? targetB : sourceA,
    bidirectional ? sourceA : targetB
  ), [sourceA, targetB, bidirectional]);

  const liveResult = useMemo(() => {
    if (!reduction.supported || !col1Output || !queryHex) return null;
    try {
      const chainSrc = bidirectional ? targetB : sourceA;
      const chainTgt = bidirectional ? sourceA : targetB;

      // GGM: PRG → PRF
      if (chainSrc === 'PRG' && chainTgt === 'PRF') {
        const prg = foundation.asPRG ? foundation.asPRG() : null;
        if (!prg) return null;
        const queryBits = queryHex.replace(/[^01]/g, '').slice(0, 8) || '10110100';
        const result = ggmPRF(prg, col1Output.slice(0, 32), queryBits);
        return {
          steps: result.steps.map(s => ({
            label: s.label, value: s.value
          })),
          output: result.output
        };
      }

      // PRF → MAC: Mac_k(m) = F_k(m)
      if (chainSrc === 'PRF' && chainTgt === 'MAC') {
        const prf = foundation.asPRF ? foundation.asPRF() : null;
        if (!prf) return null;
        const r = prf.evaluate(queryHex.slice(0, 32));
        return {
          steps: [
            { label: 'MAC(m) = F_k(m)', value: '' },
            { label: 'Message m', value: queryHex.slice(0, 32) },
            ...r.steps,
          ],
          output: r.output
        };
      }

      // OWF → PRG: hard-core bit
      if (chainSrc === 'OWF' && chainTgt === 'PRG') {
        const prg = foundation.asPRG ? foundation.asPRG() : null;
        if (!prg) return null;
        return prg.evaluate(col1Output.slice(0, 32) || queryHex);
      }

      // PRF → PRP: Luby-Rackoff (conceptual demo)
      if (chainSrc === 'PRF' && chainTgt === 'PRP') {
        const prf = foundation.asPRF ? foundation.asPRF() : null;
        if (!prf) return null;
        // 3-round Feistel
        const msg = queryHex.padEnd(32, '0').slice(0, 32);
        const L0 = msg.slice(0, 16);
        const R0 = msg.slice(16);
        const f1 = prf.evaluate(R0.padEnd(32,'0')).output.slice(0,16);
        const L1 = xorHex(L0, f1); const R1 = R0;
        const f2 = prf.evaluate(L1.padEnd(32,'0')).output.slice(0,16);
        const L2 = L1; const R2 = xorHex(R1, f2);
        const f3 = prf.evaluate(R2.padEnd(32,'0')).output.slice(0,16);
        const L3 = xorHex(L2, f3); const R3 = R2;
        return {
          steps: [
            { label: 'Input (L0, R0)', value: `${L0} | ${R0}` },
            { label: 'Round 1: L1 = L0 ⊕ F(R0)', value: `${L1} | ${R1}` },
            { label: 'Round 2: R2 = R1 ⊕ F(L1)', value: `${L2} | ${R2}` },
            { label: 'Round 3: L3 = L2 ⊕ F(R2)', value: `${L3} | ${R3}` },
          ],
          output: L3 + R3
        };
      }

      // Generic: show the reduction steps with current output
      return {
        steps: reduction.chain.map(step => ({
          label: `${step.from} → ${step.to} [${step.theorem}]`,
          value: step.description
        })),
        output: col1Output
      };
    } catch (e) {
      return { error: e.message };
    }
  }, [reduction, col1Output, queryHex, foundation, sourceA, targetB, bidirectional]);

  const targetPAInfo = PA_STATUS[targetB];
  const effectiveSrc = bidirectional ? targetB : sourceA;
  const effectiveTgt = bidirectional ? sourceA : targetB;

  return (
    <div style={S.column}>
      <div style={S.colTitle}>
        {bidirectional ? '⬅ Column 2 — Backward Reduction (B → A)' : 'Column 2 — Reduce Source to Target Primitive'}
      </div>

      <div>
        <label style={S.label}>Target Primitive B</label>
        <select
          style={S.select}
          value={targetB}
          onChange={e => onTargetChange(e.target.value)}
        >
          {PRIMITIVES.filter(p => p !== sourceA).map(p => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        {targetPAInfo && (
          <div style={{ fontSize: 10, color: COLORS.textMuted, marginTop: 3 }}>
            {targetPAInfo.pa}: {targetPAInfo.desc}
          </div>
        )}
      </div>

      <div>
        <label style={S.label}>Query / message (hex or bits)</label>
        <input
          style={S.input}
          value={queryHex}
          onChange={e => onQueryChange(e.target.value)}
          placeholder="hex or bit string, e.g. 10110101"
        />
      </div>

      {!reduction.supported ? (
        <div style={S.stubBox}>
          ⚠ No direct reduction path from {effectiveSrc} → {effectiveTgt}.
          <br />{reduction.reason}
          <br /><br />
          Try: use the bidirectional toggle, or select a different pair.
        </div>
      ) : liveResult?.error ? (
        <div style={S.errorBox}>Error: {liveResult.error}</div>
      ) : liveResult ? (
        <StepDisplay
          steps={liveResult.steps}
          output={liveResult.output}
          outputLabel={`${effectiveTgt} output`}
        />
      ) : (
        <div>
          <div style={{ color: COLORS.textMuted, fontSize: 11, marginTop: 4 }}>
            Reduction chain: {effectiveSrc} → {effectiveTgt}
          </div>
          {reduction.chain.map((step, i) => (
            <div key={i} style={{ ...S.reductionStep, marginTop: 6 }}>
              <span style={S.badge(COLORS.accent)}>{step.theorem}</span>
              <span style={{ fontSize: 11, color: COLORS.textMuted }}>
                {step.from} → {step.to}: {step.description}
              </span>
            </div>
          ))}
          <div style={{ color: COLORS.textMuted, fontSize: 11, marginTop: 10 }}>
            Enter inputs above to run the reduction live.
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof Summary Panel (bottom, collapsible)
// ─────────────────────────────────────────────────────────────────────────────
function ProofSummaryPanel({ foundationName, sourceA, targetB, bidirectional }) {
  const [open, setOpen] = useState(false);
  const effectiveSrc = bidirectional ? targetB : sourceA;
  const effectiveTgt = bidirectional ? sourceA : targetB;
  const reduction = getReductionChain(effectiveSrc, effectiveTgt);

  return (
    <div style={S.proofPanel}>
      <div style={S.proofHeader} onClick={() => setOpen(o => !o)}>
        <span>📋 Reduction Proof Summary — click to {open ? 'collapse' : 'expand'}</span>
        <span style={{ fontSize: 16 }}>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div style={S.proofContent}>
          <div style={{ marginBottom: 10, fontSize: 12, color: COLORS.textMuted }}>
            Foundation: <b style={{ color: COLORS.accentLight }}>{foundationName}</b>
            {'  →  '}
            <b style={{ color: COLORS.yellow }}>{effectiveSrc}</b>
            {'  →  '}
            <b style={{ color: COLORS.green }}>{effectiveTgt}</b>
          </div>

          {reduction.supported ? (
            reduction.chain.map((step, i) => (
              <div key={i} style={S.reductionStep}>
                <span style={S.badge(COLORS.accent)}>{step.from} → {step.to}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ color: COLORS.accentLight, fontSize: 11, fontWeight: 700 }}>
                    [{step.theorem}]
                  </div>
                  <div style={{ color: COLORS.textMuted, fontSize: 11, marginTop: 2 }}>
                    {step.description}
                  </div>
                  <div style={{ color: COLORS.textMuted, fontSize: 10, marginTop: 2 }}>
                    Security: If adversary breaks {step.to} with advantage ε,
                    it breaks {step.from} with advantage ε' ≥ ε/q
                  </div>
                </div>
                <span style={S.badge(COLORS.green)}>
                  {PA_STATUS[step.to]?.pa || '—'}
                </span>
              </div>
            ))
          ) : (
            <div style={S.stubBox}>{reduction.reason}</div>
          )}

          {/* Static chain context */}
          <div style={{ marginTop: 12, fontSize: 10, color: COLORS.textMuted, lineHeight: 1.6 }}>
            All intermediate values shown above are computed from{' '}
            <b style={{ color: COLORS.accentLight }}>{foundationName}</b> using own
            implementations (PA#1–PA#10).  No external cryptographic libraries used.
            The full Minicrypt clique is: OWF ⟺ PRG ⟺ PRF ⟺ PRP ⟺ MAC ⟺ CRHF ⟺ HMAC.
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex XOR helper (for Feistel demo)
// ─────────────────────────────────────────────────────────────────────────────
function xorHex(a, b) {
  const len = Math.max(a.length, b.length);
  const aP = a.padStart(len, '0');
  const bP = b.padStart(len, '0');
  let out = '';
  for (let i = 0; i < len; i += 2) {
    const ca = parseInt(aP.slice(i, i+2) || '00', 16);
    const cb = parseInt(bP.slice(i, i+2) || '00', 16);
    out += (ca ^ cb).toString(16).padStart(2, '0');
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main App Component
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState('explorer');
  // Foundation toggle
  const [foundationType, setFoundationType] = useState('AES');

  // Primitive selectors
  const [sourceA, setSourceA] = useState('PRG');
  const [targetB, setTargetB] = useState('PRF');

  // Inputs
  const [seedHex, setSeedHex] = useState('a3f2b1c4d5e6f708090a0b0c0d0e0f10');
  const [inputHex, setInputHex] = useState('deadbeefcafe01234567890abcdef012');
  const [queryHex, setQueryHex] = useState('10110100');

  // Bidirectional toggle
  const [bidirectional, setBidirectional] = useState(false);

  // Build foundation object (changes with type and seed)
  const foundation = useMemo(() => {
    try {
      return foundationType === 'AES'
        ? new AESFoundation(seedHex)
        : new DLPFoundation(seedHex);
    } catch {
      return null;
    }
  }, [foundationType, seedHex]);

  const foundationName = foundationType === 'AES' ? 'AES-128 (PRP)' : 'DLP (gˣ mod p)';

  // Column 1 output (piped to Column 2 as black box)
  const [col1Output, setCol1Output] = useState('');

  // Compute col1Output from foundation and sourceA
  const computedCol1 = useMemo(() => {
    if (!foundation) return '';
    try {
      switch (sourceA) {
        case 'OWF': case 'OWP': {
          const f = foundation.asOWF?.() || foundation.asOWP?.();
          return f?.evaluate(inputHex)?.output || '';
        }
        case 'PRG': {
          const g = foundation.asPRG?.();
          return g?.evaluate(seedHex)?.output || '';
        }
        case 'PRF': case 'PRP': {
          const f = foundation.asPRF?.() || foundation.asPRP?.();
          return f?.evaluate(inputHex)?.output || '';
        }
        default: {
          const f = foundation.asPRF?.();
          return f?.evaluate(inputHex)?.output || '';
        }
      }
    } catch { return ''; }
  }, [foundation, sourceA, inputHex, seedHex]);

  return (
    <div style={S.app}>
      {/* ── Top Bar ── */}
      <div style={S.topBar}>
        <span style={S.title}>CS8.401 Minicrypt Clique Explorer</span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginLeft: 32 }}>
          <button style={{...S.toggleBtn(activeTab === 'explorer'), background: activeTab === 'explorer' ? COLORS.accent : 'transparent', color: activeTab === 'explorer' ? '#fff' : COLORS.textMuted, border: `1px solid ${COLORS.accent}`, padding: '4px 12px', borderRadius: 4, cursor: 'pointer' }} onClick={() => setActiveTab('explorer')}>PA#0 Explorer</button>
          <button style={{...S.toggleBtn(activeTab === 'demos'), background: activeTab === 'demos' ? COLORS.accent : 'transparent', color: activeTab === 'demos' ? '#fff' : COLORS.textMuted, border: `1px solid ${COLORS.accent}`, padding: '4px 12px', borderRadius: 4, cursor: 'pointer' }} onClick={() => setActiveTab('demos')}>All PA#1 - PA#20 Demos</button>
        </div>


        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: COLORS.textMuted }}>Foundation:</span>
          {['AES', 'DLP'].map(f => (
            <button key={f} style={S.toggleBtn(foundationType === f)}
                    onClick={() => setFoundationType(f)}>
              {f === 'AES' ? 'AES-128 (PRP)' : 'DLP (gˣ mod p)'}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginLeft: 'auto' }}>
          <span style={{ fontSize: 11, color: COLORS.textMuted }}>Direction:</span>
          <button style={S.toggleBtn(!bidirectional)}
                  onClick={() => setBidirectional(false)}>
            Forward (A → B)
          </button>
          <button style={S.toggleBtn(bidirectional)}
                  onClick={() => setBidirectional(true)}>
            Backward (B → A)
          </button>
        </div>
      </div>

      
      {activeTab === 'explorer' ? (
        <>
{/* ── Foundation indicator ── */}
                <div style={{ padding: '6px 16px', fontSize: 11, color: COLORS.textMuted,
                              borderBottom: `1px solid ${COLORS.border}`,
                              background: COLORS.surface }}>
                  Active foundation:&nbsp;
                  <span style={{ color: COLORS.accentLight }}>{foundationName}</span>
                  &nbsp;|&nbsp; Seed/key:&nbsp;
                  <span style={{ color: COLORS.yellow }}>{seedHex.slice(0, 24)}…</span>
                  &nbsp;|&nbsp; Col 1 output (black box piped to Col 2):&nbsp;
                  <span style={{ color: COLORS.green }}>{computedCol1.slice(0, 24) || '(pending)'}{computedCol1.length > 24 ? '…' : ''}</span>
                </div>
          
                {/* ── Two-Column Main Area ── */}
                <div style={S.columns}>
                  <BuildPanel
                    foundation={foundation}
                    foundationName={foundationName}
                    sourceA={sourceA}
                    onSourceChange={setSourceA}
                    seedHex={seedHex}
                    onSeedChange={setSeedHex}
                    inputHex={inputHex}
                    onInputChange={setInputHex}
                    bidirectional={bidirectional}
                  />
          
                  <ReducePanel
                    foundation={foundation}
                    sourceA={sourceA}
                    targetB={targetB}
                    onTargetChange={setTargetB}
                    queryHex={queryHex}
                    onQueryChange={setQueryHex}
                    col1Output={computedCol1}
                    bidirectional={bidirectional}
                  />
                </div>
          
                {/* ── Bottom Proof Panel ── */}
                <ProofSummaryPanel
                  foundationName={foundationName}
                  sourceA={sourceA}
                  targetB={targetB}
                  bidirectional={bidirectional}
                />
              
        </>
      ) : (
        <div style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>
          <AllDemos />
          
        </div>
      )}
</div>
  );
}
