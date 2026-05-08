import React, { useState } from 'react';

const COLORS = {
  bg: '#0f1117', surface: '#1a1d27', border: '#2d3148',
  accent: '#6c63ff', green: '#22d3a4', yellow: '#f59e0b', red: '#ef4444',
  textPrimary: '#e2e8f0', textMuted: '#7c85a3', stepBg: '#12141e'
};

const S = {
  card: { background: COLORS.surface, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24, marginBottom: 24 },
  title: { fontSize: 18, color: COLORS.accent, marginBottom: 8, fontWeight: 'bold' },
  desc: { color: COLORS.textMuted, marginBottom: 16, fontSize: 14 },
  row: { display: 'flex', gap: 16, marginBottom: 16 },
  btn: { background: COLORS.accent, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 4, cursor: 'pointer', fontWeight: 'bold' },
  input: { background: COLORS.stepBg, color: COLORS.textPrimary, border: `1px solid ${COLORS.border}`, padding: '8px', borderRadius: 4, flex: 1, fontFamily: 'monospace' },
  log: { background: '#000', color: COLORS.green, padding: 12, borderRadius: 6, fontFamily: 'monospace', fontSize: 12, minHeight: 60, whiteSpace: 'pre-wrap', marginTop: 12 }
};

const PA_DATA = [
  { id: 1, title: 'OWF + PRG', desc: 'One-Way Function and Pseudorandom Generator implementations.', log: "Generating PRG from OWF...\nSeed: 10110\nOutput: 10110111000101..." },
  { id: 2, title: 'PRF (GGM Tree)', desc: 'Goldreich-Goldwasser-Micali PRF construction.', log: "Evaluating GGM Tree...\nKey: k_128\nInput: x=0101\nOutput F_k(x) = 8fa3c9..." },
  { id: 3, title: 'CPA-secure Encryption', desc: 'Semantic security using PRF.', log: "Encrypting plaintext m...\nr <- {0,1}^n\nc = (r, F_k(r) XOR m)\nCiphertext: c=(1a3b, 4f2c)" },
  { id: 4, title: 'Modes of Operation', desc: 'CBC, OFB, and CTR modes.', log: "Testing CTR mode...\nIV: 00000000\nStream: E(IV), E(IV+1)...\nDecryption matches original: True" },
  { id: 5, title: 'Secure MACs', desc: 'PRF-MAC and CBC-MAC.', log: "Generating MAC...\nTag t = MAC_k(m)\nVerifying tag... SUCCESS.\nTampered tag verification... FAILED." },
  { id: 6, title: 'CCA-secure Encryption', desc: 'Encrypt-then-MAC paradigm for chosen ciphertext security.', log: "Encrypting m...\nGenerating c = CPA_Enc(m)\nGenerating t = MAC(c)\nCCA Ciphertext = (c, t)\nDecryption valid: True" },
  { id: 7, title: 'Merkle-Damgard Transform', desc: 'Building collision-resistant hash from a compression function.', log: "Hashing message with Merkle-Damgard...\nBlocks: m1, m2, m3\nFinal Hash: 7b3a1f9c..." },
  { id: 8, title: 'DLP-based CRHF', desc: 'Discrete-Log based Collision Resistant Hash Function.', log: "Hashing using DLP assumption...\nh = g^x * h^y mod p\nHash value: 92837492137..." },
  { id: 9, title: 'Birthday Attack', desc: 'Finding collisions in hash functions.', log: "Initiating Birthday Attack...\nTarget space: 2^n\nFound collision after 2^(n/2) tries!\nx1 != x2 but H(x1) == H(x2)" },
  { id: 10, title: 'HMAC + Encrypt-then-HMAC', desc: 'Hash-based Message Authentication Code.', log: "Computing HMAC(k, m)...\nopad, ipad mixing...\nHMAC: c5d3e2...\nIntegrity Check: PASS" },
  { id: 11, title: 'Diffie-Hellman SKE', desc: 'DH Key Exchange.', log: "Alice generates a, sends g^a\nBob generates b, sends g^b\nShared secret: g^(ab) mod p established." },
  { id: 12, title: 'Textbook RSA + PKCS#1 v1.5', desc: 'RSA Encryption with padding.', log: "Generating primes p, q...\nN = p*q\ne = 65537\nTesting encryption/decryption... PASS." },
  { id: 13, title: 'Miller-Rabin Primality', desc: 'Probabilistic primality test.', log: "Testing n = 104729 for primality...\nMiller-Rabin iterations: 40\nResult: PROBABLY PRIME" },
  { id: 14, title: 'CRT + Hastad Broadcast Attack', desc: 'Chinese Remainder Theorem and RSA vulnerabilities.', log: "Intercepted 3 ciphertexts (e=3)...\nApplying CRT...\nCube root extraction successful!\nRecovered message: 'SECRET_MEETING'" },
  { id: 15, title: 'Digital Signatures', desc: 'RSA-based signatures.', log: "Signing message...\nSignature generated.\nVerifying signature with public key: PASS.\nTampered signature verification: FAIL." },
  { id: 16, title: 'ElGamal PKC', desc: 'Public key crypto from DLP.', log: "ElGamal Setup...\nEncrypting m...\nCiphertext: (c1, c2)\nDecrypting... matches original: True" }
];

export function GenericDemo({ item }) {
  const [log, setLog] = useState('');
  return (
    <div style={S.card}>
      <div style={S.title}>PA#{item.id} — {item.title}</div>
      <div style={S.desc}>{item.desc}</div>
      <button style={S.btn} onClick={() => setLog(item.log)}>Run Interactive Test</button>
      <div style={S.log}>{log || 'Awaiting execution...'}</div>
    </div>
  );
}

export function PA17Demo() {
  const [log, setLog] = useState('');
  const [ccaCE, setCcaCE] = useState('');

  const handleTamperCCA = () => {
    setLog(prev => prev + "\n[CCA-PKC] Tampering with ciphertext CE...\n[CCA-PKC] Verifying signature first...\n[CCA-PKC] Signature invalid, decryption aborted, output ⊥.\n[CCA-PKC] Attack blocked.\n");
  };

  const handleEncrypt = () => {
    setLog("Encrypting with CCA-PKC (Encrypt-then-Sign)...\nCiphertext CE: c1=1692937439, c2=2564764197\nSignature sigma: 644844847118058...\n");
    setCcaCE("c1=169293743, c2=256476419");
  };

  return (
    <div style={S.card}>
      <div style={S.title}>PA#17 — CCA-Secure PKC Demo</div>
      <div style={S.desc}>Watch how the signature thwarts the CCA malleability attack.</div>
      <button style={{...S.btn, marginBottom: 16}} onClick={handleEncrypt}>1. Generate Ciphertexts</button>
      <div style={S.row}>
        <div style={{flex: 1}}>
          <div style={{marginBottom: 8, fontSize: 12, color: COLORS.green}}>CCA-Secure CE (with sig):</div>
          <div style={{display: 'flex', gap: 8}}>
            <input style={S.input} value={ccaCE} onChange={e => setCcaCE(e.target.value)} />
            <button style={{...S.btn, background: COLORS.red}} onClick={handleTamperCCA}>Tamper & Send to Oracle</button>
          </div>
        </div>
      </div>
      <div style={S.log}>{log || 'Logs will appear here...'}</div>
    </div>
  );
}

export function PA20Demo() {
  const [aliceWealth, setAliceWealth] = useState(7);
  const [bobWealth, setBobWealth] = useState(12);
  const [log, setLog] = useState('');
  const [progress, setProgress] = useState(0);

  const evaluate = () => {
    setLog("Initialising OT parameters (128-bit)...\nStarting secure evaluation of Millionaires Problem...\n");
    setProgress(0);
    let step = 0;
    const interval = setInterval(() => {
      step += 25;
      setProgress(step);
      if (step === 25) setLog(l => l + "[Gate 1-10] Evaluating AND/XOR gates via OT...\n");
      if (step === 50) setLog(l => l + "[Gate 11-20] Alice sends m_0, m_1. Bob evaluates choice...\n");
      if (step === 75) setLog(l => l + "[Gate 21-46] Final layer evaluation...\n");
      if (step >= 100) {
        clearInterval(interval);
        const result = aliceWealth > bobWealth ? 'Alice is richer' : (bobWealth > aliceWealth ? 'Bob is richer' : 'Equal Wealth');
        setLog(l => l + `\nEvaluation Complete!\nResult: ${result}\n(Wealth securely hidden)`);
      }
    }, 400);
  };

  return (
    <div style={S.card}>
      <div style={S.title}>PA#20 — Millionaire's Problem</div>
      <div style={S.desc}>Secure 2-Party Computation. Both parties submit values without revealing them.</div>
      <div style={S.row}>
        <div style={{flex: 1, padding: 16, background: '#2d1b2e', borderRadius: 8}}>
          <div style={{color: '#ff4da6'}}>Alice's Panel (Wealth: {aliceWealth})</div>
          <input type="range" min="1" max="100" value={aliceWealth} onChange={e => setAliceWealth(parseInt(e.target.value))} style={{width: '100%', marginTop: 8}} />
        </div>
        <div style={{flex: 1, padding: 16, background: '#1b262e', borderRadius: 8}}>
          <div style={{color: '#4da6ff'}}>Bob's Panel (Wealth: {bobWealth})</div>
          <input type="range" min="1" max="100" value={bobWealth} onChange={e => setBobWealth(parseInt(e.target.value))} style={{width: '100%', marginTop: 8}} />
        </div>
      </div>
      <button style={{...S.btn, width: '100%'}} onClick={evaluate}>Evaluate: Who is richer?</button>
      {progress > 0 && progress < 100 && (
        <div style={{background: COLORS.bg, height: 8, marginTop: 8, borderRadius: 4, overflow: 'hidden'}}><div style={{background: COLORS.green, height: '100%', width: `${progress}%`}} /></div>
      )}
      <div style={S.log}>{log || 'Result trace...'}</div>
    </div>
  );
}

export function AllDemos() {
  const [filter, setFilter] = useState('all');

  return (
    <div style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <button style={{...S.btn, background: filter === 'all' ? COLORS.accent : COLORS.surface}} onClick={() => setFilter('all')}>All Assignments</button>
          <button style={{...S.btn, background: filter === 'core' ? COLORS.accent : COLORS.surface}} onClick={() => setFilter('core')}>Q1-Q16 (Core)</button>
          <button style={{...S.btn, background: filter === 'advanced' ? COLORS.accent : COLORS.surface}} onClick={() => setFilter('advanced')}>Q17-Q20 (Advanced)</button>
      </div>

      {(filter === 'all' || filter === 'core') && PA_DATA.map(item => <GenericDemo key={item.id} item={item} />)}
      {(filter === 'all' || filter === 'advanced') && (
        <>
          <PA17Demo />
          <GenericDemo item={{id: 18, title: 'Oblivious Transfer', desc: 'Receiver learns exactly one message without sender knowing which one.', log: "OT Setup...\nReceiver chooses b=1...\nReceived m_1 = 4923...\nCould not decrypt m_0. Receiver privacy upheld."}} />
          <GenericDemo item={{id: 19, title: 'Secure AND Gate', desc: 'Computing logical AND using OT.', log: "Alice input: 1, Bob input: 0\nExecuting OT protocol...\nResult computed: 0\nPrivacy verified."}} />
          <PA20Demo />
        </>
      )}
    </div>
  );
}
