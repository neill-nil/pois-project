/**
 * foundations.js
 * PA #0 — Foundation Layer
 *
 * Wraps PA#1 (DLP OWF/PRG) and PA#2 (AES PRF/PRP) implementations.
 * In a full deployment these would call the Python implementations via a local API
 * or WebAssembly. Here they are faithfully re-implemented in JavaScript using the
 * same algorithms (no external crypto libraries), so the app can run standalone
 * in any browser, consistent with the No-Library Rule applied to JS.
 *
 * AESFoundation: exposes asOWF(), asPRF(), asPRP()
 * DLPFoundation: exposes asOWF(), asOWP()
 * Both share a common Foundation interface.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  hex = hex.replace(/\s+/g, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal AES-128 (own implementation — matches PA#2 Python AES)
// ─────────────────────────────────────────────────────────────────────────────

const AES_SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hiBit = a & 0x80;
    a = (a << 1) & 0xff;
    if (hiBit) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function subBytes(state) {
  return state.map(b => AES_SBOX[b]);
}

function shiftRows(s) {
  // s is 16 bytes, row-major (row i = s[4i..4i+3])
  const out = new Uint8Array(16);
  // Row 0: no shift
  out[0]=s[0]; out[1]=s[1]; out[2]=s[2]; out[3]=s[3];
  // Row 1: shift left 1
  out[4]=s[5]; out[5]=s[6]; out[6]=s[7]; out[7]=s[4];
  // Row 2: shift left 2
  out[8]=s[10]; out[9]=s[11]; out[10]=s[8]; out[11]=s[9];
  // Row 3: shift left 3
  out[12]=s[15]; out[13]=s[12]; out[14]=s[13]; out[15]=s[14];
  return out;
}

function mixColumns(s) {
  const out = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const s0=s[i], s1=s[i+1], s2=s[i+2], s3=s[i+3];
    out[i]   = gmul(0x02,s0)^gmul(0x03,s1)^s2^s3;
    out[i+1] = s0^gmul(0x02,s1)^gmul(0x03,s2)^s3;
    out[i+2] = s0^s1^gmul(0x02,s2)^gmul(0x03,s3);
    out[i+3] = gmul(0x03,s0)^s1^s2^gmul(0x02,s3);
  }
  return out;
}

const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function aesKeyExpansion(key) {
  const w = [];
  for (let i = 0; i < 4; i++) {
    w.push(new Uint8Array([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]));
  }
  for (let i = 4; i < 44; i++) {
    let temp = new Uint8Array(w[i-1]);
    if (i % 4 === 0) {
      // RotWord + SubWord + Rcon
      temp = new Uint8Array([
        AES_SBOX[temp[1]] ^ RCON[(i/4)-1],
        AES_SBOX[temp[2]],
        AES_SBOX[temp[3]],
        AES_SBOX[temp[0]]
      ]);
    }
    const prev = w[i-4];
    w.push(new Uint8Array([prev[0]^temp[0], prev[1]^temp[1], prev[2]^temp[2], prev[3]^temp[3]]));
  }
  // Build 11 round keys
  const rk = [];
  for (let r = 0; r <= 10; r++) {
    const rkey = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      rkey[c*4]   = w[r*4+c][0];
      rkey[c*4+1] = w[r*4+c][1];
      rkey[c*4+2] = w[r*4+c][2];
      rkey[c*4+3] = w[r*4+c][3];
    }
    rk.push(rkey);
  }
  return rk;
}

function aesEncryptBlock(block, roundKeys) {
  let state = new Uint8Array(block);
  // AddRoundKey (round 0)
  state = xorBytes(state, roundKeys[0]);
  // Rounds 1–9
  for (let r = 1; r < 10; r++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = xorBytes(state, roundKeys[r]);
  }
  // Round 10 (no MixColumns)
  state = subBytes(state);
  state = shiftRows(state);
  state = xorBytes(state, roundKeys[10]);
  return state;
}

function aesEncrypt(keyBytes, plainBytes) {
  const rk = aesKeyExpansion(keyBytes);
  return aesEncryptBlock(plainBytes, rk);
}

// ─────────────────────────────────────────────────────────────────────────────
// AES Foundation — wraps own AES as PRF/PRP (PA#2 equivalent)
// ─────────────────────────────────────────────────────────────────────────────

export class AESFoundation {
  constructor(keyHex) {
    let keyBytes = hexToBytes(keyHex.padEnd(32, '0').slice(0, 32));
    this.keyBytes = keyBytes;
    this.keyHex = bytesToHex(keyBytes);
    this.name = 'AES-128 (PRP)';
  }

  // F_k(x) = AES_k(x)  — direct PRF evaluation
  _prf(inputBytes) {
    const padded = new Uint8Array(16);
    for (let i = 0; i < Math.min(inputBytes.length, 16); i++) padded[i] = inputBytes[i];
    return aesEncrypt(this.keyBytes.slice(0, 16), padded);
  }

  // Expose as OWF: f(k) = AES_k(0^128) XOR k  (Davies-Meyer style)
  asOWF() {
    const self = this;
    return {
      name: 'AES-OWF (Davies-Meyer)',
      evaluate: (inputHex) => {
        const x = hexToBytes(inputHex.padEnd(32, '0').slice(0, 32));
        const zero16 = new Uint8Array(16);
        const rk = aesKeyExpansion(x.slice(0, 16));
        const enc = aesEncryptBlock(zero16, rk);
        const out = xorBytes(enc, x.slice(0, 16));
        return {
          steps: [
            { label: 'Input key k', value: bytesToHex(x.slice(0, 16)) },
            { label: 'AES_k(0¹²⁸)', value: bytesToHex(enc) },
            { label: 'f(k) = AES_k(0¹²⁸) ⊕ k', value: bytesToHex(out) }
          ],
          output: bytesToHex(out)
        };
      }
    };
  }

  // PRF: F_k(x) = AES_k(x)
  asPRF() {
    const self = this;
    return {
      name: 'AES-PRF: F_k(x) = AES_k(x)',
      evaluate: (inputHex) => {
        const x = hexToBytes(inputHex.padEnd(32, '0').slice(0, 32));
        const out = self._prf(x);
        return {
          steps: [
            { label: 'Input x', value: bytesToHex(x.slice(0, 16)) },
            { label: 'AES key k', value: bytesToHex(self.keyBytes.slice(0, 16)) },
            { label: 'F_k(x) = AES_k(x)', value: bytesToHex(out) }
          ],
          output: bytesToHex(out)
        };
      }
    };
  }

  // PRP = PRF for AES (it's already a permutation)
  asPRP() {
    return this.asPRF(); // AES IS a PRP; same evaluation path
  }

  // PRG from AES-PRF: G(s) = F_s(0) || F_s(1)  (length-doubling)
  asPRG() {
    const self = this;
    return {
      name: 'PRG from AES: G(s) = AES_s(0) ∥ AES_s(1)',
      evaluate: (seedHex) => {
        const s = hexToBytes(seedHex.padEnd(32, '0').slice(0, 32));
        const rk = aesKeyExpansion(s.slice(0, 16));
        const zero = new Uint8Array(16);
        const one = new Uint8Array(16); one[15] = 1;
        const left = aesEncryptBlock(zero, rk);
        const right = aesEncryptBlock(one, rk);
        const out = new Uint8Array(32);
        out.set(left, 0); out.set(right, 16);
        return {
          steps: [
            { label: 'Seed s', value: bytesToHex(s.slice(0, 16)) },
            { label: 'AES_s(0¹²⁸)', value: bytesToHex(left) },
            { label: 'AES_s(1¹²⁸)', value: bytesToHex(right) },
            { label: 'G(s) = left ∥ right (32 bytes)', value: bytesToHex(out) }
          ],
          output: bytesToHex(out)
        };
      }
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DLP Foundation — wraps PA#1 DLP OWF/OWP
// ─────────────────────────────────────────────────────────────────────────────

// Small safe prime group for browser demos (32-bit)
// p = 4294967311 (prime), q = (p-1)/2, g = 7
// These are toy parameters — the real PA#1 uses 64-bit safe primes
const DLP_P = 4294967311n;
const DLP_Q = 2147483655n;
const DLP_G = 7n;

function modExp(base, exp, mod) {
  base = BigInt(base); exp = BigInt(exp); mod = BigInt(mod);
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// Hard-core bit: Goldreich-Levin (parity of binary dot product with random r)
// For demo: use LSB of f(x) as the hard-core predicate
function hardCoreBit(x) {
  return Number(BigInt(x) & 1n);
}

export class DLPFoundation {
  constructor(seedHex) {
    // Parse seed as an integer exponent in Z_q
    const seedBytes = hexToBytes(seedHex.padEnd(16, '0').slice(0, 16));
    const seedInt = BigInt('0x' + bytesToHex(seedBytes)) % DLP_Q;
    this.seed = seedInt === 0n ? 1n : seedInt;
    this.p = DLP_P;
    this.q = DLP_Q;
    this.g = DLP_G;
    this.name = 'DLP (gˣ mod p)';
  }

  _owf(x) {
    // f(x) = g^x mod p
    return modExp(this.g, x, this.p);
  }

  asOWF() {
    const self = this;
    return {
      name: 'DLP-OWF: f(x) = gˣ mod p',
      evaluate: (inputHex) => {
        const xBytes = hexToBytes(inputHex.padEnd(16,'0').slice(0,16));
        const x = BigInt('0x' + bytesToHex(xBytes)) % self.q || 1n;
        const fx = self._owf(x);
        return {
          steps: [
            { label: 'Input x', value: x.toString(16) },
            { label: 'g = ' + self.g.toString(16), value: '' },
            { label: 'p (safe prime)', value: self.p.toString(16) },
            { label: 'f(x) = gˣ mod p', value: fx.toString(16) }
          ],
          output: fx.toString(16)
        };
      }
    };
  }

  // DLP is already a OWP on Z_q (bijection on its range)
  asOWP() {
    return this.asOWF();
  }

  // PRG from DLP using hard-core bit construction (HILL)
  asPRG() {
    const self = this;
    return {
      name: 'PRG from DLP (HILL hard-core bit)',
      evaluate: (seedHex, outputBits = 16) => {
        const xBytes = hexToBytes(seedHex.padEnd(16,'0').slice(0,16));
        let x = BigInt('0x' + bytesToHex(xBytes)) % self.q || 1n;
        const bits = [];
        const steps = [{ label: 'Initial seed x', value: x.toString(16) }];
        for (let i = 0; i < outputBits; i++) {
          const fx = self._owf(x);
          const bit = hardCoreBit(fx);
          bits.push(bit);
          if (i < 4) {
            steps.push({ label: `b${i} = hc(g^x${i}) = hc(${fx.toString(16)})`, value: bit.toString() });
          }
          x = fx % self.q || 1n;
        }
        const outputHex = bits.reduce((acc, b, i) => {
          if (i % 8 === 0) acc += ' ';
          return acc + b;
        }, '').trim();
        steps.push({ label: `PRG output (${outputBits} bits)`, value: bits.join('') });
        return { steps, output: bits.join('') };
      }
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GGM PRF Construction (PRG → PRF via GGM tree) — PA#2 algorithm
// ─────────────────────────────────────────────────────────────────────────────

export function ggmPRF(prg, keyHex, queryBits) {
  /**
   * GGM tree: given PRG G (length-doubling), define
   *   F_k(b1...bn) = G_{b_n}(...G_{b_1}(k)...)
   * Returns: { output, path, steps }
   */
  const steps = [];
  let current = keyHex;
  steps.push({ label: 'Root (key k)', value: current, bit: null });

  for (let i = 0; i < queryBits.length; i++) {
    const b = parseInt(queryBits[i]);
    const prgResult = prg.evaluate(current);
    const output = prgResult.output;
    const left  = output.slice(0, output.length / 2);
    const right = output.slice(output.length / 2);
    current = b === 0 ? left : right;
    steps.push({
      label: `G_${b}(node) → ${b === 0 ? 'left' : 'right'} half`,
      value: current,
      bit: b
    });
  }
  return { output: current, steps };
}

// ─────────────────────────────────────────────────────────────────────────────
// Reduction Routing Table
// ─────────────────────────────────────────────────────────────────────────────

export const PRIMITIVES = ['OWF', 'OWP', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC', 'CPA-Enc', 'CCA-Enc'];

/**
 * PA implementation status map (for stub support requirement).
 * Each entry: { implemented: bool, pa: string }
 */
export const PA_STATUS = {
  OWF:     { implemented: true,  pa: 'PA#1',  desc: 'DLP: f(x) = gˣ mod p' },
  OWP:     { implemented: true,  pa: 'PA#1',  desc: 'DLP is already a OWP' },
  PRG:     { implemented: true,  pa: 'PA#1',  desc: 'HILL hard-core bit / AES CTR' },
  PRF:     { implemented: true,  pa: 'PA#2',  desc: 'GGM tree / AES directly' },
  PRP:     { implemented: true,  pa: 'PA#2',  desc: 'AES-128 (concrete PRP)' },
  MAC:     { implemented: true,  pa: 'PA#5',  desc: 'PRF-MAC: Mac_k(m) = F_k(m)' },
  CRHF:    { implemented: true,  pa: 'PA#7+8',desc: 'MD transform + DLP compression' },
  HMAC:    { implemented: true,  pa: 'PA#10', desc: 'H((k⊕opad) ∥ H((k⊕ipad)∥m))' },
  'CPA-Enc':{ implemented: true, pa: 'PA#3',  desc: '⟨r, F_k(r) ⊕ m⟩' },
  'CCA-Enc':{ implemented: true, pa: 'PA#6',  desc: 'Encrypt-then-MAC' }
};

/**
 * Routing table: returns the ordered list of reduction steps (A → B).
 * Returns array of { from, to, theorem, description }
 */
export function getReductionChain(source, target) {
  const routes = {
    'OWF→PRG':   [{ from:'OWF',  to:'PRG',  theorem:'HILL',         description:'Hard-core bit iteration: G(x)=b(x₀)∥b(x₁)∥…' }],
    'OWF→OWP':   [{ from:'OWF',  to:'OWP',  theorem:'DLP-identity', description:'DLP f(x)=gˣ mod p is already bijective on its range (OWP)' }],
    'PRG→PRF':   [{ from:'PRG',  to:'PRF',  theorem:'GGM',          description:'GGM tree: F_k(b₁…bₙ) = G_{bₙ}(…G_{b₁}(k)…)' }],
    'PRF→PRP':   [{ from:'PRF',  to:'PRP',  theorem:'Luby-Rackoff', description:'3-round Feistel network with PRF as round function' }],
    'PRF→MAC':   [{ from:'PRF',  to:'MAC',  theorem:'PRF→MAC',      description:'Mac_k(m) = F_k(m); forgery ⟹ PRF distinguisher' }],
    'PRP→MAC':   [{ from:'PRP',  to:'PRF',  theorem:'PRP/PRF switching lemma', description:'PRP ≈ PRF for large domains' },
                  { from:'PRF',  to:'MAC',  theorem:'PRF→MAC',      description:'Mac_k(m) = F_k(m)' }],
    'CRHF→HMAC': [{ from:'CRHF', to:'HMAC', theorem:'HMAC construction', description:'H((k⊕opad) ∥ H((k⊕ipad)∥m)); security from PRF of compression fn' }],
    'HMAC→MAC':  [{ from:'HMAC', to:'MAC',  theorem:'HMAC-is-MAC',  description:'HMAC is EUF-CMA secure when compression fn is PRF' }],
    'PRF→CPA':   [{ from:'PRF',  to:'CPA-Enc', theorem:'PRF→CPA',  description:'Enc(k,m)=⟨r, F_k(r)⊕m⟩; fresh random r per encryption' }],
    'CPA→CCA':   [{ from:'CPA-Enc', to:'CCA-Enc', theorem:'Encrypt-then-MAC', description:'CCA_Enc=Enc(m) then MAC(CE); verify MAC before decrypt' }],
    'OWP→PRG':   [{ from:'OWP',  to:'PRG',  theorem:'OWP+HCB→PRG', description:'G(x)=(f(x), b(x)): OWP with hard-core predicate b' }],
    'MAC→PRF':   [{ from:'MAC',  to:'PRF',  theorem:'MAC→PRF',      description:'Secure EUF-CMA MAC on random inputs is a PRF oracle' }],
    'MAC→CRHF':  [{ from:'MAC',  to:'CRHF', theorem:'MAC→CRHF via MD', description:'MAC used as MD compression fn ⟹ CRHF' }],
    'PRG→OWF':   [{ from:'PRG',  to:'OWF',  theorem:'PRG→OWF',      description:'f(s)=G(s) is a OWF: inversion recovers seed, breaking PRG' }],
    'PRF→PRG':   [{ from:'PRF',  to:'PRG',  theorem:'PRF→PRG',      description:'G(s)=F_s(0ⁿ)∥F_s(1ⁿ): length-doubling PRG from PRF' }],
    'PRP→PRF':   [{ from:'PRP',  to:'PRF',  theorem:'Switching lemma', description:'PRP on large domain is indistinguishable from PRF' }],
    'HMAC→CRHF': [{ from:'HMAC', to:'CRHF', theorem:'HMAC→CRHF',    description:'Fix k; H\'(m)=HMAC_k(m) is collision-resistant (collision = MAC forgery)' }],
    'MAC→HMAC':  [{ from:'MAC',  to:'HMAC', theorem:'MAC→HMAC',      description:'PRF-based MAC cast in double-hash HMAC structure' }],
  };

  const key = `${source}→${target}`;
  if (routes[key]) return { chain: routes[key], supported: true };

  // Try to find a path via bridging
  const bridges = {
    'OWF→PRP':   ['OWF→PRG', 'PRG→PRF', 'PRF→PRP'],
    'OWF→MAC':   ['OWF→PRG', 'PRG→PRF', 'PRF→MAC'],
    'PRG→MAC':   ['PRG→PRF', 'PRF→MAC'],
    'OWF→HMAC':  ['OWF→PRG', 'PRG→PRF', 'PRF→MAC', 'MAC→HMAC'],
    'CRHF→MAC':  ['CRHF→HMAC', 'HMAC→MAC'],
    'OWF→CPA':   ['OWF→PRG', 'PRG→PRF', 'PRF→CPA'],
    'OWF→CCA':   ['OWF→PRG', 'PRG→PRF', 'PRF→CPA', 'CPA→CCA'],
    'PRG→CCA':   ['PRG→PRF', 'PRF→CPA', 'CPA→CCA'],
    'PRF→CCA':   ['PRF→CPA', 'CPA→CCA'],
  };

  const compositeKey = `${source}→${target}`;
  if (bridges[compositeKey]) {
    const chain = bridges[compositeKey].flatMap(k => routes[k] || []);
    if (chain.length > 0) return { chain, supported: true };
  }

  return {
    chain: [],
    supported: false,
    reason: `No known direct reduction path from ${source} to ${target} in the clique. ` +
            `Try using the bidirectional toggle or select a different target.`
  };
}
