#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * `receipts-verify-action` — Standalone zero-dependency offline Class-1 verifier
 * for `.hvr` SCITT receipts, C2SP witness cosignatures, DSSE/SLSA v1.0 provenance,
 * and Gitsign commit trailers in CI (GitHub Actions) and Git `pre-commit` hooks.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const HVR_MAGIC_TAG18_ARRAY4 = Buffer.from([0xd2, 0x84]);
export const NOTE_KEY_ED25519 = 0x01;
export const NOTE_KEY_COSIGNATURE = 0x04;

// --- Minimal Deterministic CBOR Codec (RFC 8949) ----------------------------

export class CborTag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

function encodeUint(major, n) {
  const mt = major << 5;
  if (typeof n === 'number' && n < 24) return Buffer.from([mt | n]);
  const big = BigInt(n);
  if (big < 24n) return Buffer.from([mt | Number(big)]);
  if (big <= 0xffn) return Buffer.from([mt | 24, Number(big)]);
  if (big <= 0xffffn) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(Number(big), 1);
    return b;
  }
  if (big <= 0xffffffffn) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(Number(big), 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  b.writeBigUInt64BE(big, 1);
  return b;
}

export function cborEncode(val) {
  if (val === null || val === undefined) return Buffer.from([0xf6]);
  if (val === false) return Buffer.from([0xf4]);
  if (val === true) return Buffer.from([0xf5]);
  if (typeof val === 'number') {
    if (!Number.isInteger(val)) throw new Error('CBOR float not supported in deterministic profile');
    return val >= 0 ? encodeUint(0, val) : encodeUint(1, -1 - val);
  }
  if (typeof val === 'bigint') {
    return val >= 0n ? encodeUint(0, val) : encodeUint(1, -1n - val);
  }
  if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
    const b = Buffer.from(val);
    return Buffer.concat([encodeUint(2, b.length), b]);
  }
  if (typeof val === 'string') {
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([encodeUint(3, b.length), b]);
  }
  if (val instanceof CborTag) {
    return Buffer.concat([encodeUint(6, val.tag), cborEncode(val.value)]);
  }
  if (Array.isArray(val)) {
    return Buffer.concat([encodeUint(4, val.length), ...val.map((item) => cborEncode(item))]);
  }
  if (val instanceof Map) {
    const entries = [...val.entries()].map(([k, v]) => ({
      kb: cborEncode(k),
      vb: cborEncode(v),
    }));
    entries.sort((a, b) => Buffer.compare(a.kb, b.kb));
    const chunks = [encodeUint(5, entries.length)];
    for (const e of entries) chunks.push(e.kb, e.vb);
    return Buffer.concat(chunks);
  }
  if (typeof val === 'object') {
    const m = new Map();
    for (const [k, v] of Object.entries(val)) {
      if (v !== undefined) m.set(k, v);
    }
    return cborEncode(m);
  }
  throw new Error(`Unsupported CBOR type: ${typeof val}`);
}

export function cborDecode(bytes) {
  const buf = Buffer.from(bytes);
  let pos = 0;

  function readUint(ai) {
    if (ai < 24) return ai;
    if (ai === 24) {
      if (pos + 1 > buf.length) throw new Error('CBOR truncated uint8');
      return buf[pos++];
    }
    if (ai === 25) {
      if (pos + 2 > buf.length) throw new Error('CBOR truncated uint16');
      const v = buf.readUInt16BE(pos);
      pos += 2;
      return v;
    }
    if (ai === 26) {
      if (pos + 4 > buf.length) throw new Error('CBOR truncated uint32');
      const v = buf.readUInt32BE(pos);
      pos += 4;
      return v;
    }
    if (ai === 27) {
      if (pos + 8 > buf.length) throw new Error('CBOR truncated uint64');
      const v = buf.readBigUInt64BE(pos);
      pos += 8;
      return Number(v);
    }
    throw new Error(`CBOR unsupported additional info ${ai}`);
  }

  function decodeItem() {
    if (pos >= buf.length) throw new Error('CBOR unexpected EOF');
    const ib = buf[pos++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    if (major === 0) return readUint(ai);
    if (major === 1) return -1 - readUint(ai);
    if (major === 2) {
      const len = readUint(ai);
      if (pos + len > buf.length) throw new Error('CBOR truncated bstr');
      const out = buf.subarray(pos, pos + len);
      pos += len;
      return Buffer.from(out);
    }
    if (major === 3) {
      const len = readUint(ai);
      if (pos + len > buf.length) throw new Error('CBOR truncated tstr');
      const out = buf.subarray(pos, pos + len).toString('utf8');
      pos += len;
      return out;
    }
    if (major === 4) {
      const len = readUint(ai);
      const arr = [];
      for (let i = 0; i < len; i++) arr.push(decodeItem());
      return arr;
    }
    if (major === 5) {
      const len = readUint(ai);
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const k = decodeItem();
        const v = decodeItem();
        map.set(k, v);
      }
      return map;
    }
    if (major === 6) {
      const tag = readUint(ai);
      const val = decodeItem();
      return new CborTag(tag, val);
    }
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new Error(`CBOR unsupported simple/float ${ai}`);
    }
    throw new Error(`CBOR unknown major ${major}`);
  }

  const res = decodeItem();
  if (pos !== buf.length) throw new Error('CBOR trailing bytes');
  return res;
}

// --- Crypto, Merkle (RFC 9162) & C2SP Checkpoint Verification ---------------

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

export function leafHash(data) {
  return sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(data)]));
}

export function nodeHash(left, right) {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

export function verifyInclusion(leaf, proof, root) {
  const { treeSize, leafIndex, hashes } = proof;
  if (leafIndex >= treeSize || treeSize < 1) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = Buffer.from(leaf);
  for (const p of hashes) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

export function parseNoteVerifierString(s) {
  const first = s.indexOf('+');
  const second = first < 0 ? -1 : s.indexOf('+', first + 1);
  if (first <= 0 || second < 0) throw new Error(`Malformed note verifier: ${s}`);
  const name = s.slice(0, first);
  const keyId = Buffer.from(s.slice(first + 1, second), 'hex');
  const keyBytes = Buffer.from(s.slice(second + 1), 'base64');
  return {
    name,
    keyId,
    keyType: keyBytes[0],
    publicKeyRaw: keyBytes.subarray(1),
  };
}

export function ed25519KeyFromRaw(raw) {
  return crypto.createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') },
  });
}

export function publicKeyFromCoseKeyB64u(coseKeyB64u) {
  const m = cborDecode(Buffer.from(coseKeyB64u, 'base64url'));
  if (!(m instanceof Map)) throw new Error('COSE_Key must decode to a CBOR map');
  const kty = m.get(1);
  const alg = m.get(3);
  if (kty === 1) {
    // OKP Ed25519
    const x = Buffer.from(m.get(-2));
    return { key: ed25519KeyFromRaw(x), alg: alg ?? -8 };
  }
  if (kty === 2) {
    // EC2 P-256
    const x = Buffer.from(m.get(-2)).toString('base64url');
    const y = Buffer.from(m.get(-3)).toString('base64url');
    return {
      key: crypto.createPublicKey({
        format: 'jwk',
        key: { kty: 'EC', crv: 'P-256', x, y },
      }),
      alg: alg ?? -7,
    };
  }
  throw new Error(`Unsupported COSE_Key kty: ${kty}`);
}

export function verifyCheckpointWitnessQuorum(checkpointText, noteVerifiers = [], minQuorum = 3) {
  const sep = checkpointText.indexOf('\n\n');
  if (sep < 0) throw new Error('Checkpoint has no signature block');
  const body = checkpointText.slice(0, sep + 1);
  const sigBlock = checkpointText.slice(sep + 2);
  const lines = body.split('\n');
  if (lines.length < 3) throw new Error('Checkpoint body too short');
  const origin = lines[0];
  const treeSize = Number(lines[1]);
  const root = Buffer.from(lines[2], 'base64');
  if (root.length !== 32 || !Number.isSafeInteger(treeSize) || treeSize < 0) {
    throw new Error('Malformed checkpoint header fields');
  }

  const parsedVerifiers = noteVerifiers.map(parseNoteVerifierString);
  let logValid = false;
  const validWitnesses = new Set();

  for (const line of sigBlock.split('\n')) {
    if (!line.trim()) continue;
    if (!line.startsWith('— ')) throw new Error('Malformed checkpoint signature line');
    const rest = line.slice(2);
    const sp = rest.indexOf(' ');
    if (sp <= 0) throw new Error('Malformed signature entry');
    const name = rest.slice(0, sp);
    const raw = Buffer.from(rest.slice(sp + 1), 'base64');
    if (raw.length < 5) continue;
    const keyId = raw.subarray(0, 4);
    const sig = raw.subarray(4);

    const v = parsedVerifiers.find((p) => p.name === name && p.keyId.equals(keyId));
    if (!v) continue;
    const pubKey = ed25519KeyFromRaw(v.publicKeyRaw);
    if (v.keyType === NOTE_KEY_ED25519) {
      if (crypto.verify(null, Buffer.from(body, 'utf8'), pubKey, sig)) {
        logValid = true;
      }
    } else if (v.keyType === NOTE_KEY_COSIGNATURE && sig.length === 72) {
      const ts = Number(sig.readBigUInt64BE(0));
      const msg = Buffer.from(`cosignature/v1\ntime ${ts}\n${body}`, 'utf8');
      if (crypto.verify(null, msg, pubKey, sig.subarray(8))) {
        validWitnesses.add(name);
      }
    }
  }

  const quorumMet = validWitnesses.size >= minQuorum;
  return {
    origin,
    treeSize,
    root,
    logValid,
    validWitnesses: [...validWitnesses],
    quorumMet,
    minQuorum,
  };
}

// --- COSE_Sign1 & .hvr Receipt Verification ---------------------------------

function verifyCoseSignature(alg, pubKey, toBeSigned, sigBytes) {
  if (alg === -8) {
    return crypto.verify(null, toBeSigned, pubKey, sigBytes);
  }
  if (alg === -7) {
    return crypto.verify('sha256', toBeSigned, { key: pubKey, dsaEncoding: 'ieee-p1363' }, sigBytes);
  }
  return false;
}

export function parseSign1(bytes) {
  const buf = Buffer.from(bytes);
  let decoded = cborDecode(buf);
  if (decoded instanceof CborTag) {
    if (decoded.tag !== 18) throw new Error(`Expected COSE_Sign1 tag 18, got ${decoded.tag}`);
    decoded = decoded.value;
  }
  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('COSE_Sign1 must be a 4-element array');
  }
  const [protBytes, unprotMap, payload, signature] = decoded;
  const protMap = protBytes.length > 0 ? cborDecode(protBytes) : new Map();
  const kidRaw = protMap.get(4);
  const kid = Buffer.isBuffer(kidRaw) ? kidRaw.toString('utf8') : String(kidRaw ?? '');
  const alg = Number(protMap.get(1));
  return {
    protectedBytes: Buffer.from(protBytes),
    protectedHeader: protMap,
    unprotected: unprotMap instanceof Map ? unprotMap : new Map(),
    payload: payload === null ? null : Buffer.from(payload),
    signature: Buffer.from(signature),
    kid,
    alg,
  };
}

export function verifyHvrStatement(statementBytes, checkpointText, trustConfig, minWitnessQuorum = 3) {
  const checks = [];
  let parsed;
  try {
    parsed = parseSign1(statementBytes);
    checks.push({ check: 'envelope', status: 'pass', detail: 'COSE_Sign1 valid' });
  } catch (e) {
    checks.push({ check: 'envelope', status: 'fail', detail: e.message });
    return { verdict: 'FAILED', checks };
  }

  // 1. Verify Issuer signature
  const issuerEntry = (trustConfig?.issuers ?? []).find((i) => i.kid === parsed.kid);
  if (!issuerEntry) {
    checks.push({ check: 'issuer_identity', status: 'fail', detail: `Unknown issuer kid: ${parsed.kid}` });
    return { verdict: 'FAILED', checks };
  }
  const { key: issuerKey, alg: issuerAlg } = publicKeyFromCoseKeyB64u(issuerEntry.cose_key);
  const sigStruct = cborEncode(['Signature1', parsed.protectedBytes, Buffer.alloc(0), parsed.payload ?? Buffer.alloc(0)]);
  const sigOk = issuerAlg === parsed.alg && verifyCoseSignature(parsed.alg, issuerKey, sigStruct, parsed.signature);
  checks.push({
    check: 'signature',
    status: sigOk ? 'pass' : 'fail',
    detail: sigOk ? `Verified signature by ${parsed.kid} (${issuerEntry.tier})` : 'Signature verification failed',
  });

  // 2. Verify Capsule payload invariants
  let capsuleMap = null;
  try {
    capsuleMap = cborDecode(parsed.payload);
    const getField = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);
    const verdictClass = getField(capsuleMap, 'verdict_class');
    const effect = getField(capsuleMap, 'effect');
    const effectStatus = getField(effect, 'status');
    const responseDigest = getField(effect, 'response_digest');
    const effectOk = effectStatus !== 'confirmed' || (verdictClass === 'executed' && Boolean(responseDigest));
    checks.push({
      check: 'effect_binding',
      status: effectOk ? 'pass' : 'fail',
      detail: effectOk ? 'Capsule effect binding invariant holds' : 'Confirmed effect lacks response_digest or executed verdict',
    });
  } catch (e) {
    checks.push({ check: 'capsule', status: 'fail', detail: `Invalid capsule payload: ${e.message}` });
  }

  // 3. Verify RFC 9942 Inclusion Receipt & C2SP Checkpoint Witness Quorum
  const receiptsList = parsed.unprotected.get(394);
  if (!Array.isArray(receiptsList) || receiptsList.length === 0) {
    checks.push({ check: 'inclusion', status: 'fail', detail: 'No SCITT receipt attached in header 394' });
  } else if (!checkpointText) {
    checks.push({ check: 'inclusion', status: 'fail', detail: 'No checkpoint provided to verify inclusion receipt' });
  } else {
    try {
      const requiredQuorum = trustConfig?.witness_policy?.quorum ?? minWitnessQuorum;
      const cpCheck = verifyCheckpointWitnessQuorum(
        checkpointText,
        trustConfig?.note_verifiers ?? [],
        requiredQuorum,
      );

      // Reconstruct clean statement leaf bytes (without 394 receipts and -25900 timestamps)
      const cleanUnprot = new Map(parsed.unprotected);
      cleanUnprot.delete(394);
      cleanUnprot.delete(-25900);
      const cleanLeafBytes = cborEncode(
        new CborTag(18, [parsed.protectedBytes, cleanUnprot, parsed.payload, parsed.signature]),
      );
      const leaf = leafHash(cleanLeafBytes);

      let receiptOk = false;
      for (const rBytes of receiptsList) {
        const rParsed = parseSign1(rBytes);
        const logEntry = (trustConfig?.log_keys ?? []).find((l) => l.kid === rParsed.kid);
        if (!logEntry) continue;
        const { key: logKey } = publicKeyFromCoseKeyB64u(logEntry.cose_key);
        const vdp = rParsed.unprotected.get(396) ?? rParsed.protectedHeader.get(396);
        const incArr = vdp instanceof Map ? vdp.get(-1) : null;
        if (!Array.isArray(incArr) || incArr.length === 0) continue;
        const decodedProof = Buffer.isBuffer(incArr[0]) ? cborDecode(incArr[0]) : incArr;
        const proof = {
          treeSize: Number(decodedProof[0]),
          leafIndex: Number(decodedProof[1]),
          hashes: decodedProof[2].map((h) => Buffer.from(h)),
        };
        if (proof.treeSize !== cpCheck.treeSize) continue;
        if (!verifyInclusion(leaf, proof, cpCheck.root)) continue;
        const receiptSigStruct = cborEncode(['Signature1', rParsed.protectedBytes, Buffer.alloc(0), cpCheck.root]);
        if (verifyCoseSignature(rParsed.alg, logKey, receiptSigStruct, rParsed.signature)) {
          receiptOk = true;
          break;
        }
      }

      checks.push({
        check: 'inclusion',
        status: receiptOk ? 'pass' : 'fail',
        detail: receiptOk ? `RFC 9162 Merkle inclusion verified at tree size ${cpCheck.treeSize}` : 'Inclusion proof failed',
      });
      checks.push({
        check: 'checkpoint_signature',
        status: cpCheck.logValid ? 'pass' : 'fail',
        detail: cpCheck.logValid ? `Log signature verified (${cpCheck.origin})` : 'Log signature invalid',
      });
      checks.push({
        check: 'witness_quorum',
        status: cpCheck.quorumMet ? 'pass' : 'fail',
        detail: `${cpCheck.validWitnesses.length}/${cpCheck.minQuorum} valid witness cosignatures (${cpCheck.validWitnesses.join(', ')})`,
      });
    } catch (e) {
      checks.push({ check: 'inclusion', status: 'fail', detail: e.message });
    }
  }

  const verdict = checks.some((c) => c.status === 'fail') ? 'FAILED' : 'VERIFIED';
  return { verdict, checks };
}

// --- DSSE / in-toto Provenance Verification ---------------------------------

export function dssePae(payloadType, payloadBytes) {
  const typeBuf = Buffer.from(payloadType, 'utf8');
  const prefix = Buffer.from(`DSSEv1 ${typeBuf.byteLength} `, 'ascii');
  const mid = Buffer.from(` ${payloadBytes.byteLength} `, 'ascii');
  return Buffer.concat([prefix, typeBuf, mid, payloadBytes]);
}

export function verifyDsseEnvelope(envelope, publicKeyPem) {
  if (!envelope || typeof envelope.payload !== 'string' || typeof envelope.payloadType !== 'string') {
    return { valid: false, detail: 'Malformed DSSE envelope' };
  }
  const keyPem = publicKeyPem ?? envelope.verifierPublicKeyPem;
  if (!keyPem) {
    return { valid: false, detail: 'Missing DSSE verifier public key PEM' };
  }
  const payloadBytes = Buffer.from(envelope.payload, 'base64');
  const pae = dssePae(envelope.payloadType, payloadBytes);
  const pubKey = crypto.createPublicKey(keyPem);

  let sigOk = false;
  for (const sig of envelope.signatures ?? []) {
    const sigBytes = Buffer.from(sig.sig, 'base64');
    const ok =
      pubKey.asymmetricKeyType === 'ed25519'
        ? crypto.verify(null, pae, pubKey, sigBytes)
        : crypto.verify('sha256', pae, pubKey, sigBytes);
    if (ok) {
      sigOk = true;
      break;
    }
  }
  if (!sigOk) {
    return { valid: false, detail: 'DSSE PAE signature verification failed' };
  }

  const stmt = JSON.parse(payloadBytes.toString('utf8'));
  if (stmt._type !== 'https://in-toto.io/Statement/v1') {
    return { valid: false, detail: `Unexpected in-toto _type: ${stmt._type}` };
  }
  if (!Array.isArray(stmt.subject) || stmt.subject.length === 0) {
    return { valid: false, detail: 'in-toto Statement has empty subject list' };
  }
  return {
    valid: true,
    predicateType: stmt.predicateType,
    subjectCount: stmt.subject.length,
    detail: `DSSE in-toto Statement v1 verified (${stmt.predicateType}, ${stmt.subject.length} subjects)`,
  };
}

// --- Action / Pre-Commit Runner ---------------------------------------------

function collectCandidateFiles(targetPath) {
  const st = fs.statSync(targetPath);
  if (st.isFile()) return [targetPath];
  const out = [];
  for (const entry of fs.readdirSync(targetPath, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'target') continue;
    const full = path.join(targetPath, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectCandidateFiles(full));
    } else if (
      entry.name.endsWith('.hvr') ||
      entry.name.endsWith('.scitt') ||
      entry.name.endsWith('.hvr.json') ||
      entry.name.endsWith('.dsse.json')
    ) {
      out.push(full);
    }
  }
  return out;
}

export function runVerifyAction(opts = {}) {
  const targetPaths = opts.files?.length ? opts.files : [opts.path ?? '.'];
  const minWitnessQuorum = Number(opts.minWitnessQuorum ?? 3);
  const defaultTrust = opts.trustFile ? JSON.parse(fs.readFileSync(opts.trustFile, 'utf8')) : opts.trust ?? null;
  const defaultCheckpoint = opts.checkpointFile ? fs.readFileSync(opts.checkpointFile, 'utf8') : opts.checkpoint ?? null;

  const files = [];
  for (const p of targetPaths) {
    if (fs.existsSync(p)) files.push(...collectCandidateFiles(p));
  }

  const results = [];
  let dsseVerified = 0;

  for (const file of files) {
    if (file.endsWith('.dsse.json')) {
      const env = JSON.parse(fs.readFileSync(file, 'utf8'));
      const res = verifyDsseEnvelope(env, opts.dssePublicKeyPem);
      if (res.valid) dsseVerified++;
      results.push({
        file,
        kind: 'dsse',
        verdict: res.valid ? 'VERIFIED' : 'FAILED',
        detail: res.detail,
      });
      continue;
    }

    const raw = fs.readFileSync(file);
    let statementBytes;
    let checkpoint = defaultCheckpoint;
    let trust = defaultTrust;

    if (file.endsWith('.json') || (raw.length > 0 && raw[0] === 0x7b)) {
      const bundle = JSON.parse(raw.toString('utf8'));
      statementBytes = Buffer.from(bundle.statement_base64 ?? bundle.entry ?? '', 'base64');
      checkpoint = bundle.checkpoint ?? checkpoint;
      trust = bundle.trust_file ?? bundle.trust ?? trust;
    } else {
      statementBytes = raw;
    }

    const report = verifyHvrStatement(statementBytes, checkpoint, trust, minWitnessQuorum);
    results.push({
      file,
      kind: 'hvr',
      verdict: report.verdict,
      checks: report.checks,
    });
  }

  const failedCount = results.filter((r) => r.verdict !== 'VERIFIED').length;
  const verifiedCount = results.filter((r) => r.verdict === 'VERIFIED').length;
  const dsseGateOk = !opts.requireDsse || dsseVerified > 0;
  const ok = results.length > 0 && failedCount === 0 && dsseGateOk;

  return {
    ok,
    verdict: ok ? 'VERIFIED' : 'FAILED',
    verifiedCount,
    failedCount,
    dsseVerified,
    results,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const getFlag = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const targetPath = getFlag('path') ?? '.';
  const trustFile = getFlag('trust');
  const checkpointFile = getFlag('checkpoint');
  const minWitnessQuorum = Number(getFlag('min-quorum') ?? 3);
  const requireDsse = argv.includes('--require-dsse');

  const summary = runVerifyAction({
    path: targetPath,
    ...(trustFile ? { trustFile } : {}),
    ...(checkpointFile ? { checkpointFile } : {}),
    minWitnessQuorum,
    requireDsse,
  });

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(
      process.env.GITHUB_OUTPUT,
      `verdict=${summary.verdict}\nverified_count=${summary.verifiedCount}\nreport_json=${JSON.stringify(summary)}\n`,
    );
  }
  console.log(JSON.stringify(summary, null, 2));
  process.exit(summary.ok ? 0 : 1);
}
