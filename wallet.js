bitcoin.initEccLib(ecc);

import * as bitcoin from 'https://esm.sh/bitcoinjs-lib@6.1.6?bundle';
import ecc from 'https://esm.sh/@bitcoinerlab/secp256k1@1.0.5';
import * as noble from 'https://esm.sh/@noble/secp256k1@1.7.1';
import ECPairFactory from 'https://esm.sh/ecpair@3.0.0';
import { Buffer } from 'https://esm.sh/buffer@6.0.3';
import "./messaging.js";
import * as bip39 from 'https://esm.sh/bip39@3.1.0';
import bip32Factory from 'https://esm.sh/bip32@4.0.0';
window.Buffer = Buffer;

const bip32 = bip32Factory(ecc);


const wrappedEcc = {
  ...ecc,
  pointFromScalar: (d, compressed) => {
    const result = ecc.pointFromScalar(d, compressed);
    return result ? Buffer.from(result) : null;
  },
  pointAdd: (p1, p2, compressed) => {
    const result = ecc.pointAdd(p1, p2, compressed);
    return result ? Buffer.from(result) : null;
  },
  pointAddScalar: (p, scalar, compressed) => {
    const result = ecc.pointAddScalar(p, scalar, compressed);
    return result ? Buffer.from(result) : null;
  },
  pointMultiply: (p, scalar, compressed) => {
    const result = ecc.pointMultiply(p, scalar, compressed);
    return result ? Buffer.from(result) : null;
  },
  privateAdd: (d, tweak) => {
    const result = ecc.privateAdd(d, tweak);
    return result ? Buffer.from(result) : null;
  },
  privateNegate: (d) => Buffer.from(ecc.privateNegate(d)),
  sign: (hash, privateKey, extraEntropy) => Buffer.from(ecc.sign(hash, privateKey, extraEntropy)),
  signSchnorr: (hash, privateKey, extraEntropy) => Buffer.from(ecc.signSchnorr(hash, privateKey, extraEntropy))
};
bitcoin.initEccLib(wrappedEcc);

let hdWallet = null;
let currentMnemonic = null;

const ECPair = ECPairFactory(wrappedEcc);

const NITO_NETWORK = {
  messagePrefix: '\x18NITO Signed Message:\n',
  bech32: 'nito',
  bip32: { public: 0x0488B21E, private: 0x0488ADE4 },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80
};

const NODE_URL = '/api/';
let MIN_FEE_RATE = 0.00001;
let DYNAMIC_FEE_RATE = null;
let MEMPOOL_MIN_FEE = null;
let RELAY_FEE = null;

const DUST_RELAY_AMOUNT = 3000;
const DUST_AMOUNT = {
  p2pkh: 546,
  p2wpkh: 294,
  p2sh: 540,
  p2tr: 330
};
const MIN_CONSOLIDATION_FEE = 0.00005;
const MAX_UTXOS_PER_BATCH = 500;

let walletAddress = '';
let legacyAddress = '';
let p2shAddress = '';
let bech32Address = '';
let taprootAddress = '';
let walletPublicKey = null;
let walletKeyPair = null;
let taprootPublicKey = null;
let taprootKeyPair = null;
let consolidateButtonInjected = false;
let lastActionTime = null;
let inactivityTimeout = null;
let timerInterval = null;
let importType = '';



const HD_START_RANGE = 512;
const HD_MAX_RANGE = 50000;
const HD_RANGE_SAFETY = 16;

function getHdAccountNode(family) {
  if (!hdWallet) throw new Error('HD wallet not initialized');
  if (family === 'legacy')  return hdWallet.derivePath("m/44'/0'/0'");
  if (family === 'p2sh')    return hdWallet.derivePath("m/49'/0'/0'");
  if (family === 'bech32')  return hdWallet.derivePath("m/84'/0'/0'");
  if (family === 'taproot') return hdWallet.derivePath("m/86'/0'/0'");
  throw new Error('Unknown family for HD');
}


function familyToDescriptorPrefix(family) {
  if (family === 'bech32') return 'wpkh';
  if (family === 'taproot') return 'tr';
  if (family === 'legacy') return 'pkh';
  throw new Error('Unknown family');
}


function xpubForFamily(family) {
  const acct = getHdAccountNode(family).neutered();
  return acct.toBase58();
}

function makeFamilyDescriptor(family, branch) {
  const xpub = xpubForFamily(family);
  if (family === 'p2sh') return `sh(wpkh(${xpub}/${branch}/*))`;
  const prefix = familyToDescriptorPrefix(family);
  return `${prefix}(${xpub}/${branch}/*)`;
}


function parseDescBranchIndex(desc) {
  try {

    const m = desc.match(/\/(0|1)\/(\d+)\)?/);
    if (!m) return null;
    return { branch: parseInt(m[1], 10), index: parseInt(m[2], 10) };
  } catch (_) { return null; }
}

function deriveKeyFor(family, branch, index) {
  const account = getHdAccountNode(family);
  const node = account.derive(branch).derive(index);
  const keyPair = ECPair.fromPrivateKey(node.privateKey, { network: NITO_NETWORK });
  const pub = Buffer.from(node.publicKey);
  if (family === 'taproot') {
    return { keyPair, tapInternalKey: toXOnly(pub), scriptType: 'p2tr' };
  }
  if (family === 'legacy') {
    return { keyPair, scriptType: 'p2pkh' };
  }
  if (family === 'p2sh') {
    const p2w = bitcoin.payments.p2wpkh({ pubkey: pub, network: NITO_NETWORK });
    return { keyPair, redeemScript: p2w.output, scriptType: 'p2sh' };
  }
  return { keyPair, scriptType: 'p2wpkh' };
}


function prederiveMapForRange(family, branch, start, count) {
  const byScriptHex = {};
  const network = NITO_NETWORK;
  const account = getHdAccountNode(family);
  const branchNode = account.derive(branch);
  for (let i = start; i < start + count; i++) {
    const node = branchNode.derive(i);
    const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
    const pub = Buffer.from(node.publicKey);
    if (family === 'bech32') {
      const pay = bitcoin.payments.p2wpkh({ pubkey: pub, network });
      if (!pay.output) continue;
      byScriptHex[pay.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2wpkh' };
    } else if (family === 'taproot') {
      const internal = toXOnly(pub);
      const pay = bitcoin.payments.p2tr({ internalPubkey: internal, network });
      if (!pay.output) continue;
      byScriptHex[pay.output.toString('hex').toLowerCase()] = { keyPair, tapInternalKey: internal, scriptType: 'p2tr' };
    } else if (family === 'legacy') {
      const pay = bitcoin.payments.p2pkh({ pubkey: pub, network });
      if (!pay.output) continue;
      byScriptHex[pay.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2pkh' };
    } else if (family === 'p2sh') {
      const p2w = bitcoin.payments.p2wpkh({ pubkey: pub, network });
      const p2s = bitcoin.payments.p2sh({ redeem: p2w, network });
      if (!p2s.output) continue;
      byScriptHex[p2s.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2sh', redeemScript: p2w.output };
    }
  }
  return byScriptHex;
}


async function scanBranch(family, branch, startRange=HD_START_RANGE) {
  const descriptor = makeFamilyDescriptor(family, branch);
  let current = startRange;
  let all = [];
  let seen = new Set();
  let maxIndex = -1;

  while (true) {
    let scan;
    try {
      scan = await rpc('scantxoutset', ['start', [{ desc: descriptor, range: current }]]);
    } catch (e) {
      console.error('scantxoutset failed for descriptor', descriptor, e);

      break;
    }
    const unspents = (scan && scan.unspents) ? scan.unspents : [];
    if (!unspents.length && current > startRange) {
      break;
    }


    let map = null;

    for (const u of unspents) {
      const key = `${u.txid}:${u.vout}`;
      if (seen.has(key)) continue;
      seen.add(key);

      let branchIdx = branch;
      let index = null;
      if (u.desc) {
        const parsed = parseDescBranchIndex(u.desc);
        if (parsed) {
          branchIdx = parsed.branch;
          index = parsed.index;
        }
      }
      let enriched = {
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        scriptPubKey: u.scriptPubKey,
        scriptType: detectScriptType(u.scriptPubKey)
      };


      if (index !== null) {
        const keyInfo = deriveKeyFor(family, branchIdx, index);
        enriched.keyPair = keyInfo.keyPair;
        if (keyInfo.tapInternalKey) enriched.tapInternalKey = keyInfo.tapInternalKey;
      } else {
        if (!map) map = prederiveMapForRange(family, branch, 0, current);
        const info = map[(u.scriptPubKey || '').toLowerCase()];
        if (info) {
          enriched.keyPair = info.keyPair;
          if (info.tapInternalKey) enriched.tapInternalKey = info.tapInternalKey;
          if (info.redeemScript) enriched.redeemScript = info.redeemScript;
        }
      }
      if (index !== null) {
        if (index > maxIndex) maxIndex = index;
      }
      all.push(enriched);
    }


    if (maxIndex >= current - HD_RANGE_SAFETY && current < HD_MAX_RANGE) {
      current = Math.min(current * 2, HD_MAX_RANGE);
      continue;
    }
    break;
  }

  return { utxos: all, maxIndex };
}


async function scanHdUtxosForFamilyDescriptor(family) {
  try {
    const res0 = await scanBranch(family, 0, HD_START_RANGE);
    const res1 = await scanBranch(family, 1, HD_START_RANGE);
    const seen = new Set();
    const all = [];
    for (const u of [...res0.utxos, ...res1.utxos]) {
      const k = `${u.txid}:${u.vout}`;
      if (seen.has(k)) continue;
      seen.add(k);
      all.push(u);
    }
    return all;
  } catch (e) {
    console.warn('Descriptor scan failed, falling back to legacy HD scan:', e?.message || e);
    if (typeof scanHdUtxosForFamily === 'function') {
      return await scanHdUtxosForFamily(family);
    }
    throw e;
  }
}


const HD_SCAN_CHUNK = 50;
const HD_SCAN_MAX_CHUNKS = 40;

function deriveHdChunk(family, start, count) {
  if (!hdWallet) throw new Error('HD wallet not initialized');
  const byScriptHex = {};
  const descriptors = [];
  const network = NITO_NETWORK;

  if (family === 'bech32') {
    const account = hdWallet.derivePath("m/84'/0'/0'");
    for (let chain = 0; chain <= 1; chain++) {
      const branch = account.derive(chain);
      for (let i = start; i < start + count; i++) {
        const node = branch.derive(i);
        if (!node.privateKey) continue;
        const pubkey = Buffer.from(node.publicKey);
        const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
        const pay = bitcoin.payments.p2wpkh({ pubkey, network });
        if (!pay.address || !pay.output) continue;
        const scriptHex = pay.output.toString('hex').toLowerCase();
        byScriptHex[scriptHex] = { keyPair, scriptType: 'p2wpkh' };
        descriptors.push(`addr(${pay.address})`);
      }
    }
  } else if (family === 'taproot') {
    const account = hdWallet.derivePath("m/86'/0'/0'");
    for (let chain = 0; chain <= 1; chain++) {
      const branch = account.derive(chain);
      for (let i = start; i < start + count; i++) {
        const node = branch.derive(i);
        if (!node.privateKey) continue;
        const internal = toXOnly(node.publicKey);
        const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
        const pay = bitcoin.payments.p2tr({ internalPubkey: internal, network });
        if (!pay.address || !pay.output) continue;
        const scriptHex = pay.output.toString('hex').toLowerCase();
        byScriptHex[scriptHex] = { keyPair, scriptType: 'p2tr', tapInternalKey: internal };
        descriptors.push(`addr(${pay.address})`);
      }
    }
  } else if (family === 'legacy' || family === 'p2sh') {
    const account = getHdAccountNode(family);
    for (let chain = 0; chain <= 1; chain++) {
      const branch = account.derive(chain);
      for (let i = start; i < start + count; i++) {
        const node = branch.derive(i);
        if (!node.privateKey) continue;
        const pubkey = Buffer.from(node.publicKey);
        const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
        if (family === 'legacy') {
          const pay = bitcoin.payments.p2pkh({ pubkey, network });
          if (!pay.address || !pay.output) continue;
          byScriptHex[pay.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2pkh' };
          descriptors.push(`addr(${pay.address})`);
        } else {
          const p2w = bitcoin.payments.p2wpkh({ pubkey, network });
          const p2s = bitcoin.payments.p2sh({ redeem: p2w, network });
          if (!p2s.address || !p2s.output) continue;
          byScriptHex[p2s.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2sh', redeemScript: p2w.output };
          descriptors.push(`addr(${p2s.address})`);
        }
      }
    }
  } else {
    throw new Error('Unknown family for HD derivation');
  }

  return { descriptors, byScriptHex };
}


async function scanHdUtxosForFamily(family) {
  const allUtxos = [];
  const seen = new Set();

  for (let chunk = 0; chunk < HD_SCAN_MAX_CHUNKS; chunk++) {
    const start = chunk * HD_SCAN_CHUNK;
    const { descriptors, byScriptHex } = deriveHdChunk(family, start, HD_SCAN_CHUNK);
    if (!descriptors.length) break;

    let scan;
    try {
      scan = await rpc('scantxoutset', ['start', descriptors]);
    } catch (e) {
      console.error('scantxoutset failed for HD scan chunk', { family, start }, e);
      break;
    }
    const unspents = (scan && scan.unspents) ? scan.unspents : [];
    if (!unspents.length && chunk > 0) {
      break;
    }

    for (const u of unspents) {
      if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) continue;
      const scriptHex = u.scriptPubKey.toLowerCase();
      const keyInfo = byScriptHex[scriptHex];
      const key = `${u.txid}:${u.vout}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const scriptType = detectScriptType(u.scriptPubKey);
      const enriched = {
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        scriptPubKey: u.scriptPubKey,
        scriptType
      };
      if (keyInfo) {
        enriched.keyPair = keyInfo.keyPair;
        if (keyInfo.tapInternalKey) enriched.tapInternalKey = keyInfo.tapInternalKey;
      }
      allUtxos.push(enriched);
    }
  }

  return allUtxos;
}
;


i18next
  .use(window.i18nextHttpBackend)
  .init({
    lng: 'fr',
    fallbackLng: 'en',
    backend: {
      loadPath: '/langs/{{lng}}.json'
    }
  }, (err, t) => {
    if (err) {
      console.error('Erreur i18next:', err);
      return;
    }
    updateTranslations();
  });

function updateTranslations() {

  document.querySelectorAll('[data-i18n]').forEach(element => {
    const key = element.getAttribute('data-i18n');
    if (key.startsWith('[placeholder]')) {
      const actualKey = key.replace('[placeholder]', '');
      element.setAttribute('placeholder', i18next.t(actualKey));
    } else {
      element.textContent = i18next.t(key);
    }
  });


  const h1 = document.querySelector('h1');
  if (h1 && h1.childNodes[1]) {
    h1.childNodes[1].textContent = i18next.t('title');
  }


  const warning = document.querySelector('.warning');
  if (warning) {
    warning.innerHTML = DOMPurify.sanitize(i18next.t('generate_section.warning'));
  }


  const consolidateButton = document.getElementById('consolidateButton');
  if (consolidateButton) {
    consolidateButton.textContent = i18next.t('send_section.consolidate_button');
  }
}

const RAW_TX_CACHE = new Map();
async function fetchRawTxHex(txid) {
  if (RAW_TX_CACHE.has(txid)) return RAW_TX_CACHE.get(txid);
  const raw = await rpc('getrawtransaction', [txid, true]);
  const hex = raw && raw.hex ? raw.hex : null;
  if (!hex) throw new Error(`rawtx introuvable pour ${txid}`);
  RAW_TX_CACHE.set(txid, hex);
  return hex;
}
async function rpc(method, params) {
  const conflictMethods = ['scantxoutset'];

  if (conflictMethods.includes(method)) {
    while (true) {
      try {
        const res = await fetch(NODE_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
        });
        const text = await res.text();
        if (method !== 'getnetworkinfo' && method !== 'estimatesmartfee') console.log('RPC raw response:', text);
        if (!res.ok) throw new Error(`HTTP Error: ${res.status} - ${text}`);
        const data = JSON.parse(text);
        if (data.error) throw new Error(data.error.message);
        return data.result;

      } catch (e) {
        if (e.message.includes("Scan already in progress")) {
          const delay = Math.random() * 3000 + 2000;
          console.log(`⏳ ${method} en attente, retry dans ${Math.round(delay/1000)}s...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        throw e;
      }
    }
  } else {
    try {
      const res = await fetch(NODE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
      });
      const text = await res.text();
        if (method !== 'getnetworkinfo' && method !== 'estimatesmartfee') console.log('RPC raw response:', text);
      if (!res.ok) throw new Error(`HTTP Error: ${res.status} - ${text}`);
      const data = JSON.parse(text);
      if (data.error) throw new Error(data.error.message);
      return data.result;
    } catch (e) {
      console.error('RPC Error:', method, e);
      throw e;
    }
  }
}


async function fetchCounter() {
  try {
    const res = await fetch('/api/get-counter', { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();
    return data.count;
  } catch (e) {
    console.error('Error fetching counter:', e);
    return 0;
  }
}


async function incrementCounter() {
  try {
    const res = await fetch('/api/increment-counter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'increment' })
    });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();
    return data.count;
  } catch (e) {
    console.error('Error incrementing counter:', e);
    return null;
  }
}


async function updateCounterDisplay() {
  const counterElement = document.getElementById('keyCounter');
  if (counterElement) {
    const count = await fetchCounter();
    counterElement.textContent = count;
  }
}


async function filterOpReturnUtxos(utxos) {

  const filteredUtxos = utxos.filter(utxo => utxo.amount >= 0.00005);
  console.log(`UTXOs filtrés: ${filteredUtxos.length}/${utxos.length} (> 0.00005 NITO)`);
  return filteredUtxos;
}

async function showSuccessPopup(txid) {
  const body = document.body;
  let progress = 0;
  const explorerUrl = await getExplorerUrl(txid);
  const popup = document.createElement('div');
  popup.className = 'popup';
  popup.style.position = 'fixed';
  popup.style.top = '50%';
  popup.style.left = '50%';
  popup.style.transform = 'translate(-50%, -50%)';
  popup.style.background = body.classList.contains('dark-mode') ? '#37474f' : 'white';
  popup.style.padding = '20px';
  popup.style.border = '1px solid black';
  popup.style.zIndex = '1000';
  popup.style.color = body.classList.contains('dark-mode') ? '#e0e0e0' : '#1e3a8a';
  popup.innerHTML = DOMPurify.sanitize(`
    <p>${i18next.t('popup.success.message')}</p>
    <p>${i18next.t('popup.success.progress')} <span id="progress"></span>%</p>
    <p>${i18next.t('popup.success.txid')} <span id="txidLink">${txid}</span></p>
    <button id="closeSuccessPopup">${i18next.t('popup.success.close')}</button>
  `);
  document.body.appendChild(popup);

  const progressSpan = popup.querySelector('#progress');
  const txidLinkSpan = popup.querySelector('#txidLink');
  const closeButton = document.getElementById('closeSuccessPopup');

  const updateProgress = async () => {
    if (progress < 100) {
      progress = Math.min(progress + 1.67, 100);
      progressSpan.textContent = Math.round(progress);
      try {
        const confirmed = await checkTransactionConfirmation(txid);
        if (confirmed) {
          progress = 100;
          progressSpan.textContent = progress;
          txidLinkSpan.innerHTML = `<a href="${explorerUrl}" target="_blank" rel="noopener noreferrer">${txid}</a>`;
        } else {
          setTimeout(updateProgress, 10000);
        }
      } catch {
        setTimeout(updateProgress, 10000);
      }
    }
  };

  updateProgress();
  closeButton.onclick = () => document.body.removeChild(popup);
}


function showLoadingSpinner() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.style.display = 'block';
}

function hideLoadingSpinner() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.style.display = 'none';
}


async function initNetworkParams() {
  try {
    const feeInfo = await rpc('estimatesmartfee', [6]);
    const rawFeeRate = (feeInfo && typeof feeInfo.feerate === 'number') ? feeInfo.feerate : MIN_FEE_RATE;
    DYNAMIC_FEE_RATE = Math.max(rawFeeRate, MIN_FEE_RATE);

    try {
      const mem = await rpc('getmempoolinfo', []);
      if (mem && typeof mem.mempoolminfee === 'number') MEMPOOL_MIN_FEE = mem.mempoolminfee;
    } catch (e) {
      console.warn('getmempoolinfo failed:', e?.message || e);
    }
    try {
      const net = await rpc('getnetworkinfo', []);
      if (net && typeof net.relayfee === 'number') RELAY_FEE = net.relayfee;
    } catch (e) {
      console.warn('getnetworkinfo failed:', e?.message || e);
    }

    console.log('Fee params', { DYNAMIC_FEE_RATE, MEMPOOL_MIN_FEE, RELAY_FEE });
  } catch (e) {
    console.error('initNetworkParams failed:', e);
  }
}


function genAddr(type) {
  try {
    if (!['legacy', 'p2sh', 'bech32'].includes(type)) {
      throw new Error(i18next.t('errors.invalid_address_type'));
    }
    const kp = ECPair.makeRandom({ network: NITO_NETWORK });
    const privateKeyHex = Buffer.from(kp.privateKey).toString('hex');
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    let address;
    if (type === 'legacy') {
      address = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK }).address;
    } else if (type === 'p2sh') {
      const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
      address = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK }).address;
    } else {
      address = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK }).address;
    }
    return { address, privateKeyHex, privateKey: kp.toWIF() };
  } catch (e) {
    console.error('Error in genAddr:', e);
    throw e;
  }
}

async function validateAddress(address) {
  try {
    const result = await rpc('validateaddress', [address]);
    return result.isvalid;
  } catch (e) {
    console.error('Error validating address:', e);
    return false;
  }
}

/**
 * Génère une phrase mnémonique HD
 */
function generateHDMnemonic(wordCount = 12) {
  try {
    const entropyBits = wordCount === 24 ? 256 : 128;
    const entropyBytes = entropyBits / 8;
    const entropy = window.crypto.getRandomValues(new Uint8Array(entropyBytes));
    const entropyHex = Array.from(entropy).map(x => x.toString(16).padStart(2, '0')).join('');
    return bip39.entropyToMnemonic(entropyHex);
  } catch (e) {
    console.error('Erreur génération mnémonique:', e);
    throw new Error(i18next.t('errors.mnemonic_generation_error'));
  }
}

/**
 * Importe un wallet HD depuis mnémonique ou xprv
 */
function importHDWallet(seedOrXprv, passphrase = '') {
  try {
    let seed;

    if (seedOrXprv.startsWith('xprv')) {

      hdWallet = bip32.fromBase58(seedOrXprv);
      currentMnemonic = null;
    } else {

      const mnemonic = seedOrXprv.trim();
      if (!bip39.validateMnemonic(mnemonic)) {
         throw new Error(i18next.t('errors.invalid_mnemonic'));
      }

      seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
      hdWallet = bip32.fromSeed(seed);
      currentMnemonic = mnemonic;
    }


    const bech32Node = hdWallet.derivePath("m/84'/0'/0'/0/0");


    const legacyNode = hdWallet.derivePath("m/44'/0'/0'/0/0");


    const p2shNode   = hdWallet.derivePath("m/49'/0'/0'/0/0");
    const pubkey = Buffer.from(bech32Node.publicKey);
    const keyPair = ECPair.fromPrivateKey(bech32Node.privateKey, { network: NITO_NETWORK });

    const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(legacyNode.publicKey), network: NITO_NETWORK  });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkey, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({
  redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }),
  network: NITO_NETWORK 
});


    const taprootNode = hdWallet.derivePath("m/86'/0'/0'/0/0");
    const tapInternalPubkey = toXOnly(taprootNode.publicKey);
    const p2tr = bitcoin.payments.p2tr({ internalPubkey: tapInternalPubkey, network: NITO_NETWORK });


    const taprootKeyPair = ECPair.fromPrivateKey(taprootNode.privateKey, { network: NITO_NETWORK });

    return {
      legacy: p2pkh.address,
      p2sh: p2sh.address,
      bech32: p2wpkh.address,
      taproot: p2tr.address,
      keyPair: keyPair,
      publicKey: pubkey,
      taprootKeyPair: taprootKeyPair,
      taprootPublicKey: tapInternalPubkey,
      hdMasterKey: hdWallet.toBase58(),
      mnemonic: currentMnemonic
    };

  } catch (e) {
    console.error('Erreur importation HD:', e);
    throw new Error(i18next.t('errors.hd_import_error', { message: e.message }));
  }
}

function importWIF(wif) {
  try {
    const kp = ECPair.fromWIF(wif, NITO_NETWORK);
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(legacyNode.publicKey), network: NITO_NETWORK  });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({
  redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }),
  network: NITO_NETWORK 
});
    return {
      legacy: p2pkh.address,
      p2sh: p2sh.address,
      bech32: p2wpkh.address,
      keyPair: kp,
      publicKey: pubkeyBuffer
    };
  } catch (e) {
    console.error('Error in importWIF:', e);
    throw new Error(i18next.t('errors.invalid_wif', { message: e.message }));
  }
}

function importHex(hex) {
  try {
    const privateKeyBuffer = Buffer.from(hex, 'hex');
    if (privateKeyBuffer.length !== 32) {
      throw new Error(i18next.t('errors.invalid_hex_length'));
    }
    const kp = ECPair.fromPrivateKey(privateKeyBuffer, { network: NITO_NETWORK });
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
    return {
      legacy: p2pkh.address,
      p2sh: p2sh.address,
      bech32: p2wpkh.address,
      keyPair: kp,
      publicKey: pubkeyBuffer
    };
  } catch (e) {
    console.error('Error in importHex:', e);
    throw new Error(i18next.t('errors.invalid_hex', { message: e.message }));
  }
}


async function utxosAllForBech32() {
  const families = ['bech32', 'p2sh', 'legacy'];
  const parts = [];
  for (const fam of families) {
    try { parts.push(await scanHdUtxosForFamilyDescriptor(fam)); }
    catch (e) {
      if (typeof scanHdUtxosForFamily === 'function') parts.push(await scanHdUtxosForFamily(fam));
    }
  }
  const seen = new Set();
  const merged = [];
  for (const arr of parts) for (const u of arr) {
    const k = `${u.txid}:${u.vout}`;
    if (seen.has(k)) continue; seen.add(k);
    merged.push(u);
  }
  return merged;
}
async function utxos(addr) {
  try {
    if (importType === 'hd' && hdWallet) {
      const addrType = getAddressType(addr);
      if (addrType === 'p2wpkh') {
        return await utxosAllForBech32();
      } else if (addrType === 'p2tr') {
        return await scanHdUtxosForFamilyDescriptor('taproot');
      }
    }
    const scan = await rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    if (!scan.success || !scan.unspents) return [];
    return scan.unspents.map(u => {
      if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) {
        throw new Error(`Invalid scriptPubKey for UTXO ${u.txid}:${u.vout}`);
      }
      const scriptType = detectScriptType(u.scriptPubKey);
      if (scriptType === 'unknown') {
        throw new Error(`Non-compliant scriptPubKey: ${u.scriptPubKey}`);
      }
      return {
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        scriptPubKey: u.scriptPubKey,
        scriptType
      };
    });
  } catch (e) {
    console.error('Error fetching UTXO:', e);
    throw e;
  }
}



async function balance(addr) {
  try {
    if (importType === 'hd' && hdWallet) {
      const ins = await utxos(addr);
      return ins.reduce((sum, u) => sum + (u.amount || 0), 0);
    }
    const scan = await rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    return scan.total_amount || 0;
  } catch (e) {
    console.error('Error fetching balance:', e);
    throw e;
  }
}


function getAddressType(addr) {
  try {
    if (addr.startsWith('nito1p')) return 'p2tr';
    if (addr.startsWith('nito1')) return 'p2wpkh';
    if (addr.startsWith('3')) return 'p2sh';
    if (addr.startsWith('1')) return 'p2pkh';
    return 'unknown';
  } catch (e) {
    console.error('Error detecting address:', e);
    return 'unknown';
  }
}

function isSegWit(type) {
  return type === 'p2wpkh';
}

function detectScriptType(scriptPubKey) {
  try {
    const script = Buffer.from(scriptPubKey, 'hex');
    if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
      return 'p2pkh';
    } else if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
      return 'p2wpkh';
    } else if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
      return 'p2sh';
    } else if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
      return 'p2tr';
    }
    return 'unknown';
  } catch (e) {
    console.error('Error detecting script:', e);
    return 'unknown';
  }
}

function getDustThreshold(scriptType) {
  return DUST_AMOUNT[scriptType] || DUST_AMOUNT.p2sh;
}


function _inputVBytes(type) {
  const inputSizes = { p2pkh: 148, p2wpkh: 68, p2sh: 91, p2tr: 57.5 };
  return inputSizes[type] || inputSizes.p2wpkh;
}
function _outputVBytes(type) {
  const outputSizes = { p2pkh: 34, p2wpkh: 31, p2sh: 32, p2tr: 43 };
  return outputSizes[type] || outputSizes.p2wpkh;
}
function estimateVBytes(inputType, numInputs, outputTypesArray) {
  const overhead = 10;
  const inSize = _inputVBytes(inputType) * numInputs;
  const outSize = (outputTypesArray || []).reduce((s, t) => s + _outputVBytes(t), 0);
  return overhead + inSize + outSize;
}
/**
 * Estimate fee with possible change output, iterating once:
 * - assume change exists -> compute fee -> compute change
 * - if change < dust for changeType, recompute as single-output (no change)
 * Returns { vbytes, fee, outputs: ['dest'] or ['dest','change'], changeSats }
 */
function estimateFeeWithChange(totalSats, targetSats, inputType, numInputs, destType, changeType) {
  const dustChange = getDustThreshold((changeType === 'p2tr') ? 'p2tr' : 'p2wpkh');

  const withChangeVBytes = estimateVBytes(inputType, numInputs, [destType, changeType || 'p2wpkh']);
  const withChangeFee = feeForVsize(withChangeVBytes);
  const change = totalSats - targetSats - withChangeFee;
  if (change >= dustChange) {
    return { vbytes: withChangeVBytes, fee: withChangeFee, outputs: [destType, changeType || 'p2wpkh'], changeSats: change };
  }

  const noChangeVBytes = estimateVBytes(inputType, numInputs, [destType]);
  const noChangeFee = feeForVsize(noChangeVBytes);
  return { vbytes: noChangeVBytes, fee: noChangeFee, outputs: [destType], changeSats: 0 };
}
function estimateTxSize(scriptType, numInputs, numOutputs, destScriptType) {
  const inputSizes = { p2pkh: 148, p2wpkh: 68, p2sh: 91, p2tr: 57.5 };
  const outputSizes = { p2pkh: 34, p2wpkh: 31, p2sh: 32, p2tr: 43 };
  const overhead = 10;
  const inputSize = inputSizes[scriptType] || inputSizes.p2wpkh;
  const outputSize = outputSizes[destScriptType] || outputSizes.p2wpkh;
  return overhead + inputSize * numInputs + outputSize * numOutputs;
}

function effectiveFeeRate() {
  const dyn = (typeof DYNAMIC_FEE_RATE === 'number' && !isNaN(DYNAMIC_FEE_RATE)) ? DYNAMIC_FEE_RATE : 0;
  const mem = (typeof MEMPOOL_MIN_FEE === 'number' && !isNaN(MEMPOOL_MIN_FEE)) ? MEMPOOL_MIN_FEE : 0;
  const rel = (typeof RELAY_FEE === 'number' && !isNaN(RELAY_FEE)) ? RELAY_FEE : 0;
  return Math.max(dyn, mem, rel, MIN_FEE_RATE);
}

function feeForVsize(vbytes) {

  const rate = effectiveFeeRate();
  return Math.ceil((vbytes) * (rate * 1.2 * 1e8) / 1000);
}
try { window.feeForVsize = feeForVsize; window.effectiveFeeRate = effectiveFeeRate; } catch(_) {}


function toXOnly(pubkey) {
  return Buffer.from(pubkey.slice(1, 33));
}

function tapTweakHash(pubKey, h = Buffer.alloc(0)) {
  return bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([toXOnly(pubKey), h]));
}

function tweakSigner(signer, opts = {}) {
  let privateKey = Uint8Array.from(signer.privateKey);
  const publicKey = Uint8Array.from(signer.publicKey);
  if (publicKey[0] === 3) {
    privateKey = wrappedEcc.privateNegate(privateKey);
  }
  const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
  const tweak = Uint8Array.from(tapTweakHash(signer.publicKey, tweakHash));
  const tweakedPrivateKey = wrappedEcc.privateAdd(privateKey, tweak);
  if (!tweakedPrivateKey) {
    throw new Error('Invalid tweaked private key!');
  }
  const tweakedPublicKey = wrappedEcc.pointFromScalar(tweakedPrivateKey, true);
  return {
    publicKey: tweakedPublicKey,
    signSchnorr: (hash) => wrappedEcc.signSchnorr(hash, tweakedPrivateKey, noble.utils.randomBytes(32))
  };
}

function getP2SHAddress(pubkeyBuffer) {
  try {
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }), network: NITO_NETWORK });
    return { address: p2sh.address, redeemScript: p2wpkh.output };
  } catch (e) {
    console.error('Error converting to P2SH:', e);
    throw e;
  }
}

async function transferToP2SH(amt) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));
  const { address: p2shAddress } = getP2SHAddress(walletPublicKey);
  return await signTxWithPSBT(p2shAddress, amt);
}


async function signTxBatch(to, amt, specificUtxos, isConsolidation = true) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));

  const destScriptType = getAddressType(to);
  const target = Math.round(amt * 1e8);

  const selectedIns = [...specificUtxos];
  const est = estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
  const fees = est.fee;
  const total = selectedIns.reduce((s,u)=> s + Math.round(u.amount*1e8), 0);
  const change = total - target - fees;
  if (change < 0 && !isConsolidation) throw new Error(i18next.t('errors.insufficient_funds'));

  const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
  psbt.setVersion(2);

  for (const u of selectedIns) {
    const scriptBuffer = Buffer.from(u.scriptPubKey, 'hex');
    if (u.scriptType === 'p2wpkh') {
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) } });
    } else if (u.scriptType === 'p2sh') {
      const redeem = u.redeemScript || bitcoin.payments.p2wpkh({ pubkey: Buffer.from((u.keyPair||walletKeyPair).publicKey), network: NITO_NETWORK }).output;
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) }, redeemScript: redeem });
    } else if (u.scriptType === 'p2pkh') {
      const hex = await fetchRawTxHex(u.txid);
      psbt.addInput({ hash: u.txid, index: u.vout, nonWitnessUtxo: Buffer.from(hex, 'hex') });
    } else if (u.scriptType === 'p2tr') {
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) }, tapInternalKey: (u.tapInternalKey || taprootPublicKey) });
    } else {
      throw new Error(i18next.t('errors.unsupported_address_type'));
    }
  }

  if (target < getDustThreshold(destScriptType)) {
    throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: getDustThreshold(destScriptType) }));
  }
  psbt.addOutput({ address: to, value: target });

  if (change > getDustThreshold('p2wpkh') && !isConsolidation) {
    psbt.addOutput({ address: walletAddress, value: change });
  }

  for (let i=0;i<selectedIns.length;i++) {
    const u = selectedIns[i];
    if (u.scriptType === 'p2tr') {
      const kp = (u.keyPair || taprootKeyPair);
      const tweaked = tweakSigner(kp, { network: NITO_NETWORK });
      psbt.signInput(i, tweaked);
    } else {
      const kp = (u.keyPair || walletKeyPair);
      psbt.signInput(i, kp);
    }
  }

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  const hex = tx.toHex();
  return { hex, actualFees: fees / 1e8 };
}


function estimateVBytesMixed(inputs, outputTypes){
  const overhead = 10;
  const inSize = inputs.reduce((s,u)=> s + _inputVBytes(u.scriptType), 0);
  const outSize = (outputTypes||[]).reduce((s,t)=> s + _outputVBytes(t), 0);
  return overhead + inSize + outSize;
}
function estimateFeeWithChangeMixed(selectedIns, targetSats, destType, changeType){
  const dustChange = getDustThreshold((changeType === 'p2tr') ? 'p2tr' : 'p2wpkh');
  const withChangeVBytes = estimateVBytesMixed(selectedIns, [destType, changeType || 'p2wpkh']);
  const withChangeFee = feeForVsize(withChangeVBytes);
  const totalSats = selectedIns.reduce((s,u)=> s + Math.round((u.amount||0)*1e8), 0);
  const change = totalSats - targetSats - withChangeFee;
  if (change >= dustChange) {
    return { vbytes: withChangeVBytes, fee: withChangeFee, outputs: [destType, changeType || 'p2wpkh'], changeSats: change };
  }
  const noChangeVBytes = estimateVBytesMixed(selectedIns, [destType]);
  const noChangeFee = feeForVsize(noChangeVBytes);
  return { vbytes: noChangeVBytes, fee: noChangeFee, outputs: [destType], changeSats: 0 };
}
async function signTx(to, amt, isConsolidation = false) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));

  const ins = await utxos(walletAddress);
  if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

  const workingIns = isConsolidation ? ins : await filterOpReturnUtxos(ins);
  if (!workingIns.length) throw new Error(i18next.t('errors.utxo_opreturn_consolidate'));

  const destScriptType = getAddressType(to);
  const target = Math.round(amt * 1e8);

  workingIns.sort((a,b)=> b.amount - a.amount);
  const selectedIns = [];
  let total = 0;
  for (const u of workingIns) {
    selectedIns.push(u);
    total += Math.round(u.amount * 1e8);
    if (!isConsolidation) {
      const est = estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
      if (total >= target + est.fee + getDustThreshold('p2wpkh')) break;
    }
  }

  const est = estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
  const fees = est.fee;
  const change = selectedIns.reduce((s,u)=> s + Math.round(u.amount*1e8),0) - target - fees;
  if (change < 0) throw new Error(i18next.t('errors.insufficient_funds'));

  const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
  psbt.setVersion(2);

  for (const u of selectedIns) {
    const scriptBuffer = Buffer.from(u.scriptPubKey, 'hex');
    if (u.scriptType === 'p2wpkh') {
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) } });
    } else if (u.scriptType === 'p2sh') {
      const redeem = u.redeemScript || bitcoin.payments.p2wpkh({ pubkey: Buffer.from((u.keyPair||walletKeyPair).publicKey), network: NITO_NETWORK }).output;
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) }, redeemScript: redeem });
    } else if (u.scriptType === 'p2pkh') {
      const hex = await fetchRawTxHex(u.txid);
      psbt.addInput({ hash: u.txid, index: u.vout, nonWitnessUtxo: Buffer.from(hex, 'hex') });
    } else if (u.scriptType === 'p2tr') {
      psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount*1e8) }, tapInternalKey: (u.tapInternalKey || taprootPublicKey) });
    } else {
      throw new Error(i18next.t('errors.unsupported_address_type'));
    }
  }

  if (target < getDustThreshold(destScriptType)) {
    throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: getDustThreshold(destScriptType) }));
  }
  psbt.addOutput({ address: to, value: target });

  if (change > getDustThreshold('p2wpkh') && !isConsolidation) {
    psbt.addOutput({ address: walletAddress, value: change });
  }

  for (let i = 0; i < selectedIns.length; i++) {
    const u = selectedIns[i];
    if (u.scriptType === 'p2tr') {
      const kp = (u.keyPair || taprootKeyPair);
      const tweaked = tweakSigner(kp, { network: NITO_NETWORK });
      psbt.signInput(i, tweaked);
    } else {
      const kp = (u.keyPair || walletKeyPair);
      psbt.signInput(i, kp);
    }
  }

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  const hex = tx.toHex();
  return { hex, actualFees: fees / 1e8 };
}


async function signTxWithPSBT(to, amt, isConsolidation = false) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));

  console.log('Starting transaction preparation for:', to, 'Amount:', amt, 'Consolidation:', isConsolidation);

  const ins = await utxos(walletAddress);
  if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

  const workingIns = isConsolidation ? ins : await filterOpReturnUtxos(ins);
  if (!workingIns.length) throw new Error('Aucun UTXO disponible (tous contiennent des OP_RETURN, veuillez consolider les UTXOs)');

  const sendScriptType = getAddressType(walletAddress);
  const destScriptType = getAddressType(to);
  console.log('Script type - sender:', sendScriptType, 'destination:', destScriptType);

  const target = Math.round(amt * 1e8);
  workingIns.sort((a, b) => b.amount - a.amount);
  let total = 0;
  const selectedIns = [];

  for (const u of workingIns) {
    selectedIns.push(u);
    total += Math.round(u.amount * 1e8);


    if (!isConsolidation) {
      const _feeEst = estimateFeeWithChange(total, target, sendScriptType, selectedIns.length, destScriptType, 'p2wpkh'); const estimatedSize = _feeEst.vbytes; const estimatedFees = _feeEst.fee;

      if (total >= target + estimatedFees + getDustThreshold(sendScriptType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
        break;
      }
    }


  }

  const _feeEst = estimateFeeWithChange(total, target, sendScriptType, selectedIns.length, destScriptType, 'p2wpkh'); const txSize = _feeEst.vbytes; const inputFee = _feeEst.fee;



  console.log('Estimated size:', txSize, 'vbytes, Fee:', inputFee / 1e8, 'NITO, Selected UTXOs:', selectedIns.length);

  const fees = inputFee;
  const change = total - target - fees;
  if (change < 0) throw new Error(i18next.t('errors.insufficient_funds'));

  const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
  psbt.setVersion(2);

  for (const utxo of selectedIns) {
    let scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
    if (!(scriptBuffer instanceof Buffer)) {
      scriptBuffer = Buffer.from(scriptBuffer);
    }
    if (sendScriptType === 'p2wpkh') {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) }
      });
    } else if (sendScriptType === 'p2sh') {
      const { redeemScript } = getP2SHAddress(walletPublicKey);
      if (!redeemScript) throw new Error(i18next.t('errors.invalid_redeem_script'));
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) },
        redeemScript: redeemScript
      });
    } else if (sendScriptType === 'p2pkh') {
      const rawTx = await rpc('getrawtransaction', [utxo.txid, true]);
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        nonWitnessUtxo: Buffer.from(rawTx.hex, 'hex')
      });
    } else if (sendScriptType === 'p2tr') {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) },
        tapInternalKey: (utxo.tapInternalKey || taprootPublicKey)
      });
    } else {
      throw new Error(i18next.t('errors.unsupported_address_type'));
    }
  }

  if (target < getDustThreshold(destScriptType)) {
    throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: getDustThreshold(destScriptType) }));
  }
  psbt.addOutput({ address: to, value: target });

  if (change > getDustThreshold(sendScriptType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
    psbt.addOutput({ address: walletAddress, value: change });
  }

  for (let i = 0; i < selectedIns.length; i++) {
    const u = selectedIns[i];
    if (sendScriptType === 'p2tr') {
      const kp = (u.keyPair || taprootKeyPair);
      const tweakedSigner = tweakSigner(kp, { network: NITO_NETWORK });
      psbt.signInput(i, tweakedSigner);
    } else {
      const kp = (u.keyPair || walletKeyPair);
      psbt.signInput(i, kp);
    }
  }

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  const hex = tx.toHex();

  console.log('Transaction PSBT hex:', hex, 'TXID:', tx.getId());
  return { hex, actualFees: fees / 1e8 };
}

async function getExplorerUrl(txid) {
  const primaryUrl = `https://explorer.nito.network/tx/${txid}`;
  const fallbackUrl = `https://nitoexplorer.org/tx/${txid}`;
  try {
    const res = await fetch('https://explorer.nito.network', { method: 'HEAD', mode: 'cors' });
    if (res.ok) return primaryUrl;
    console.log('Primary explorer unavailable, using fallback');
    return fallbackUrl;
  } catch (e) {
    console.error('Error checking explorer:', e);
    return fallbackUrl;
  }
}

async function checkTransactionConfirmation(txid) {
  const primaryApi = `https://explorer.nito.network/ext/gettx/${txid}`;
  const fallbackApi = `https://nitoexplorer.org/ext/gettx/${txid}`;
  try {
    const res = await fetch(primaryApi);
    if (res.ok) {
      const data = await res.json();
      return data.confirmations >= 1;
    }
    const fallbackRes = await fetch(fallbackApi);
    if (fallbackRes.ok) {
      const fallbackData = await fallbackRes.json();
      return fallbackData.confirmations >= 1;
    }
    return false;
  } catch (e) {
    console.error('Error checking confirmation via API:', e);
    return false;
  }
}

async function consolidateUtxos() {
  updateLastActionTime();
  const body = document.body;
  console.log('Consolidate UTXOs button clicked');

  try {
    if (!walletAddress || !walletKeyPair || !walletPublicKey || !bech32Address) {
      alert(i18next.t('errors.import_first'));
      console.error('Wallet or addresses not initialized');
      return;
    }

    const sourceType = $('debitAddressType').value;
    if (!['bech32', 'p2tr'].includes(sourceType)) {
      alert(i18next.t('errors.consolidation_bech32_only'));
      console.error('Invalid source type:', sourceType);
      return;
    }

    const sourceAddress = (sourceType === 'p2tr') ? taprootAddress : bech32Address;
    console.log('Consolidating UTXOs for:', sourceAddress);

    showLoadingSpinner();


    const initialUtxos = await utxos(sourceAddress);
    if (initialUtxos.length < 2) {
      hideLoadingSpinner();
      alert(i18next.t('errors.consolidation_low_utxo'));
      console.log('Less than 2 UTXOs found:', initialUtxos.length);
      return;
    }

    console.log('Initial UTXOs to consolidate:', initialUtxos.length);


    const utxosPerBatch = 500;
    const estimatedSteps = Math.ceil(initialUtxos.length / utxosPerBatch);
    const maxSteps = Math.min(estimatedSteps, 100);

    console.log(`Consolidation estimée: ${estimatedSteps} étapes pour ${initialUtxos.length} UTXOs`);


    const confirm = await new Promise(resolve => {
      hideLoadingSpinner();
      const popup = document.createElement('div');
      popup.className = 'popup';
      popup.style.position = 'fixed';
      popup.style.top = '50%';
      popup.style.left = '50%';
      popup.style.transform = 'translate(-50%, -50%)';
      popup.style.background = body.classList.contains('dark-mode') ? '#37474f' : 'white';
      popup.style.padding = '20px';
      popup.style.border = '1px solid black';
      popup.style.zIndex = '1000';
      popup.style.color = body.classList.contains('dark-mode') ? '#e0e0e0' : '#1e3a8a';
      popup.innerHTML = DOMPurify.sanitize(`
        <p>${initialUtxos.length} UTXOs → 1 UTXO</p>
        <button id="confirmConsolidate">Confirmer</button>
        <button id="cancelConsolidate">Annuler</button>
      `);
      document.body.appendChild(popup);

      const confirmBtn = document.getElementById('confirmConsolidate');
      const cancelBtn = document.getElementById('cancelConsolidate');

      confirmBtn.onclick = () => {
        document.body.removeChild(popup);
        resolve(true);
      };
      cancelBtn.onclick = () => {
        document.body.removeChild(popup);
        resolve(false);
      };
    });

    if (!confirm) {
      console.log('Consolidation cancelled by user');
      return;
    }

    showLoadingSpinner();

    const originalWalletAddress = walletAddress;
    const originalWalletPublicKey = walletPublicKey;
    const originalWalletKeyPair = walletKeyPair;

    walletAddress = sourceAddress;
    walletPublicKey = (sourceType === 'p2tr') ? taprootPublicKey : walletPublicKey;
    walletKeyPair = (sourceType === 'p2tr') ? taprootKeyPair : walletKeyPair;

    let currentUtxos = [...initialUtxos];
    let stepCount = 1;
    let totalSuccess = 0;
    let lastTxid = null;
    let consecutiveIdenticalScans = 0;
    const MAX_IDENTICAL_SCANS = 3;

    try {

      while (currentUtxos.length > 1 && stepCount <= maxSteps) {
        console.log(`${stepCount}/${maxSteps} (${Math.round((stepCount/maxSteps)*100)}%) - UTXOs restants: ${currentUtxos.length}`);


        if (currentUtxos.length === 1) {
          console.log("🎯 CONSOLIDATION TERMINÉE : 1 seul UTXO restant");
          break;
        }


        if (currentUtxos.length === 2 && consecutiveIdenticalScans >= MAX_IDENTICAL_SCANS) {
          console.log(`🎯 CONSOLIDATION RÉUSSI : 2 UTXOs restants après ${consecutiveIdenticalScans} scans identiques`);
          break;
        }


        const batchUtxos = currentUtxos.slice(0, 500);

        currentUtxos = currentUtxos.slice(500);


        let batchTotal = 0;
        for (const u of batchUtxos) {
          batchTotal += Math.round(u.amount * 1e8);
        }

        const target = batchTotal;

        if (target < getDustThreshold(sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
          console.log(`⚠️ Montant trop petit (${target / 1e8} NITO), consolidation terminée`);
          break;
        }



        const inputSize = (sourceType === 'p2tr') ? 57.5 : 68;
        const destScriptType = getAddressType(sourceAddress);
        let estimatedFees = feeForVsize(estimateVBytes(sourceType, batchUtxos.length, [destScriptType]));


        const amountToSend = (batchTotal - estimatedFees) / 1e8;

        console.log(`🚀 Étape ${stepCount} - Consolidation: ${batchUtxos.length} UTXOs → 1 UTXO (${amountToSend} NITO)`);

        try {
          const result = await signTxBatch(sourceAddress, amountToSend, batchUtxos, true);
          const hex = result.hex;
          const txid = await rpc('sendrawtransaction', [hex]);

          console.log(`✅ Étape ${stepCount} réussie, TXID: ${txid}`);
          totalSuccess++;
          lastTxid = txid;


          console.log('⏳ Attente confirmation (5 secondes)...');
          await new Promise(resolve => setTimeout(resolve, 5000));

          console.log(`📊 UTXOs restants à traiter: ${currentUtxos.length}`);


          if (currentUtxos.length <= 1) {
            console.log("🎯 CONSOLIDATION COMPLÈTE !");
            break;
          }

          consecutiveIdenticalScans = 0;

        } catch (error) {
          if (error.message.includes('txn-mempool-conflict')) {
            console.log(`⚠️ Conflit mempool étape ${stepCount}, attente 10s...`);
            await new Promise(resolve => setTimeout(resolve, 10000));
            currentUtxos = await utxos(sourceAddress);
            continue;
          } else if (error.message.includes('Transaction already in block chain')) {
            console.log(`✅ Transaction déjà confirmée à l'étape ${stepCount}`);
            totalSuccess++;
            await new Promise(resolve => setTimeout(resolve, 5000));
            currentUtxos = await utxos(sourceAddress);
          } else {
            throw error;
          }
        }

        stepCount++;
      }

      hideLoadingSpinner();

      if (totalSuccess > 0) {
        await showSuccessPopup(lastTxid);
        alert(i18next.t('consolidation_final_completed', { transactions: totalSuccess, utxos: currentUtxos.length }));
        setTimeout(() => $('refreshBalanceButton').click(), 3000);
      } else if (currentUtxos.length <= 1) {
        alert(i18next.t('consolidation_single_utxo_completed'));
        setTimeout(() => $('refreshBalanceButton').click(), 3000);
      } else {
        alert(i18next.t('consolidation_stopped', { utxos: currentUtxos.length }));
      }

    } catch (e) {
      hideLoadingSpinner();
      alert(i18next.t('errors.consolidation_error', { message: e.message }));
      console.error('Consolidation error:', e);
    } finally {
      walletAddress = originalWalletAddress;
      walletPublicKey = originalWalletPublicKey;
      walletKeyPair = originalWalletKeyPair;
    }

  } catch (e) {
    hideLoadingSpinner();
    alert(i18next.t('errors.consolidation_error', { message: e.message }));
    console.error('Consolidation error:', e);
  }
}

function copyToClipboard(id) {
  updateLastActionTime();
  const element = document.getElementById(id);
  if (!element) {
    alert(i18next.t('errors.element_not_found'));
    return;
  }
  if (element.classList.contains('blurred')) {
    alert(i18next.t('errors.reveal_to_copy'));
    return;
  }
  const text = element.textContent || element.innerText || '';
  if (!text) {
    alert(i18next.t('errors.nothing_to_copy'));
    return;
  }
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  textArea.style.top = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    alert(i18next.t('copied'));
  } catch (err) {
    console.error('Copy error:', err);
    alert(i18next.t('errors.copy_error'));
  } finally {
    document.body.removeChild(textArea);
  }
}

function updateInactivityTimer() {
  if (timerInterval) clearInterval(timerInterval);
  const timerElement = document.getElementById('inactivityTimer');
  if (!timerElement) return;

  const updateTimer = () => {
    if (!lastActionTime) {
      timerElement.textContent = '[10:00]';
      return;
    }
    const now = Date.now();
    const elapsed = now - lastActionTime;
    const remaining = Math.max(0, 600000 - elapsed);
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    if (remaining <= 0) clearInterval(timerInterval);
  };

  updateTimer();
  timerInterval = setInterval(updateTimer, 1000);
}

function updateLastActionTime() {
  lastActionTime = Date.now();
  if (inactivityTimeout) clearTimeout(inactivityTimeout);
  inactivityTimeout = setTimeout(clearSensitiveData, 600000);
  updateInactivityTimer();
}

function clearSensitiveData() {

  const privateKeyHex = document.getElementById('privateKeyHex');
  const privateKey = document.getElementById('privateKey');
  const hdMasterKey = document.getElementById('hdMasterKey');
  const mnemonicPhrase = document.getElementById('mnemonicPhrase');
  const generatedAddress = document.getElementById('generatedAddress');

  if (privateKeyHex) privateKeyHex.textContent = '';
  if (privateKey) privateKey.textContent = '';
  if (hdMasterKey) hdMasterKey.textContent = '';
  if (mnemonicPhrase) mnemonicPhrase.textContent = '';
  if (generatedAddress) generatedAddress.innerHTML = '';




  console.log('Generated keys cleared, imported wallet preserved');
}

window.copyToClipboard = copyToClipboard;
window.consolidateUtxos = consolidateUtxos;

const $ = id => document.getElementById(id);

window.addEventListener('load', async () => {
  console.log('Loading wallet.js');

  try {
    const requiredIds = [
      'themeToggle', 'languageSelect', 'generateButton', 'importWalletButton', 'refreshBalanceButton',
      'prepareTxButton', 'broadcastTxButton', 'cancelTxButton',
      'destinationAddress', 'amountNito', 'feeNito', 'debitAddressType', 'privateKeyWIF',
      'walletAddress', 'walletBalance', 'txHexContainer', 'signedTx', 'copyTxHex', 'generatedAddress',
      'inactivityTimer',
      'keyCounter',
      'hdMasterKey', 'mnemonicPhrase', 'copyHdKey', 'copyMnemonic',
      'revealHdKey', 'revealMnemonic'
    ];

    for (const id of requiredIds) {
      if (!$(id)) {
        console.error(`Element ${id} missing`);
        alert(i18next.t('errors.missing_element', { id }));
        return;
      }
    }

    await initNetworkParams();
    const info = await rpc('getblockchaininfo');
    console.log('Connected to NITO node:', info);


    await updateCounterDisplay();

    const themeToggle = $('themeToggle');
    const body = document.body;

    function setTheme(isDark) {
      if (isDark) {
        body.classList.add('dark-mode');
        themeToggle.textContent = '☀️';
        localStorage.setItem('theme', 'dark');
      } else {
        body.classList.remove('dark-mode');
        themeToggle.textContent = '🌙';
        localStorage.setItem('theme', 'light');
      }
    }

    const savedTheme = localStorage.getItem('theme');
    setTheme(savedTheme === 'dark');

    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        setTheme(!body.classList.contains('dark-mode'));
      });
    }

    $('languageSelect').addEventListener('change', (e) => {
      i18next.changeLanguage(e.target.value, (err) => {
        if (err) {
          console.error('Error changing language:', err);
          return;
        }
        updateTranslations();
      });
    });

    updateInactivityTimer();

    $('copyTxHex').onclick = () => copyToClipboard('signedTx');
    $('copyHdKey').onclick = () => copyToClipboard('hdMasterKey');
    $('copyMnemonic').onclick = () => copyToClipboard('mnemonicPhrase');

    $('generateButton').onclick = async () => {
      updateLastActionTime();
      try {

        const mnemonic = generateHDMnemonic(24);
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const hdWallet = bip32.fromSeed(seed);
        const hdMasterKey = hdWallet.toBase58();


        const bech32Node = hdWallet.derivePath("m/84'/0'/0'/0/0");


        const legacyNode = hdWallet.derivePath("m/44'/0'/0'/0/0");


        const p2shNode   = hdWallet.derivePath("m/49'/0'/0'/0/0");
        const pubkey = Buffer.from(bech32Node.publicKey);
        const keyPair = ECPair.fromPrivateKey(bech32Node.privateKey, { network: NITO_NETWORK });

        const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(legacyNode.publicKey), network: NITO_NETWORK });
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkey, network: NITO_NETWORK });
        const p2sh = bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }), network: NITO_NETWORK });


        const taprootNode = hdWallet.derivePath("m/86'/0'/0'/0/0");
        const tapInternalPubkey = toXOnly(taprootNode.publicKey);
        const p2tr = bitcoin.payments.p2tr({ internalPubkey: tapInternalPubkey, network: NITO_NETWORK });

        const taprootKeyPair = ECPair.fromPrivateKey(taprootNode.privateKey, { network: NITO_NETWORK });

        const addresses = {
          legacy: p2pkh.address,
          p2sh: p2sh.address,
          bech32: p2wpkh.address,
          taproot: p2tr.address
        };

        if (!await validateAddress(addresses.legacy) ||
            !await validateAddress(addresses.p2sh) ||
            !await validateAddress(addresses.bech32) ||
            !await validateAddress(addresses.taproot)) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }


        $('hdMasterKey').textContent = hdMasterKey;
        $('mnemonicPhrase').textContent = mnemonic;


        $('hdMasterKey').classList.add('blurred');
        $('mnemonicPhrase').classList.add('blurred');


        $('generatedAddress').innerHTML = DOMPurify.sanitize(`
          Bech32: <span id="generatedBech32Address">${addresses.bech32}</span> <button class="copy-btn" id="copyGeneratedBech32Addr">📋</button><br>
          Bech32m (Taproot): <span id="generatedTaprootAddress">${addresses.taproot}</span> <button class="copy-btn" id="copyGeneratedTaprootAddr">📋</button>
        `);

        const copyGeneratedBech32Addr = $('copyGeneratedBech32Addr');
        if (copyGeneratedBech32Addr) copyGeneratedBech32Addr.onclick = () => copyToClipboard('generatedBech32Address');

        const copyGeneratedTaprootAddr = $('copyGeneratedTaprootAddr');
        if (copyGeneratedTaprootAddr) copyGeneratedTaprootAddr.onclick = () => copyToClipboard('generatedTaprootAddress');


        const wifSection = document.getElementById('wifSection');
        const hexSection = document.getElementById('hexSection');
        if (wifSection) wifSection.style.display = 'none';
        if (hexSection) hexSection.style.display = 'none';


        const revealHdKey = $('revealHdKey');
        const revealMnemonic = $('revealMnemonic');
        if (revealHdKey) {
          revealHdKey.onclick = () => {
            revealHdKey.disabled = true;
            $('hdMasterKey').classList.remove('blurred');
            setTimeout(() => {
              $('hdMasterKey').classList.add('blurred');
              revealHdKey.disabled = false;
            }, 10000);
          };
        }
        if (revealMnemonic) {
          revealMnemonic.onclick = () => {
            revealMnemonic.disabled = true;
            $('mnemonicPhrase').classList.remove('blurred');
            setTimeout(() => {
              $('mnemonicPhrase').classList.add('blurred');
              revealMnemonic.disabled = false;
            }, 10000);
          };
        }


        await incrementCounter();
        await updateCounterDisplay();
      } catch (e) {
        alert(i18next.t('errors.generation_error', { message: e.message }));
        console.error('Generation error:', e);
      }
    };

    $('importWalletButton').onclick = async () => {
      updateLastActionTime();
      try {
        const input = $('privateKeyWIF').value.trim();
        const hdPassphrase = '';

        if (!input) {
          alert(i18next.t('errors.import_empty'));
          return;
        }

        let addresses;

        importType = '';

        if (input.startsWith('xprv')) {

          addresses = importHDWallet(input, hdPassphrase);
          importType = 'hd';
        } else if (input.split(' ').length >= 12 && input.split(' ').length <= 24) {

          addresses = importHDWallet(input, hdPassphrase);
          importType = 'hd';
        } else if (/^[0-9a-fA-F]{64}$/.test(input)) {

          addresses = importHex(input);
          importType = 'single';
        } else {

          addresses = importWIF(input);
          importType = 'single';
        }

        if (!await validateAddress(addresses.legacy) ||
            !await validateAddress(addresses.p2sh) ||
            !await validateAddress(addresses.bech32) ||
            (importType === 'hd' && addresses.taproot && !await validateAddress(addresses.taproot))) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        legacyAddress = addresses.legacy;
        p2shAddress = addresses.p2sh;
        bech32Address = addresses.bech32;
        taprootAddress = addresses.taproot || '';
        walletAddress = bech32Address;
        walletPublicKey = addresses.publicKey;
        walletKeyPair = addresses.keyPair;
        taprootPublicKey = addresses.taprootPublicKey || null;
        taprootKeyPair = addresses.taprootKeyPair || null;

        const bech32Balance = await balance(bech32Address);
        let taprootBalance = 0;
        let addressDisplay = `
          Bech32: <span id="bech32Address">${bech32Address}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (${bech32Balance.toFixed(8)} )
        `;

        if (importType === 'hd') {
          taprootBalance = await balance(taprootAddress);
          addressDisplay += `<br>Bech32m (Taproot): <span id="taprootAddress">${taprootAddress}</span> <button class="copy-btn" id="copyTaprootAddr">📋</button> (${taprootBalance.toFixed(8)} )`;
        }

        $('walletAddress').innerHTML = DOMPurify.sanitize(addressDisplay);
        $('walletBalance').innerHTML = `Bech32: ${bech32Balance.toFixed(8)}` + (importType === 'hd' ? ` | Bech32m (Taproot): ${taprootBalance.toFixed(8)} ` : ' NITO');

        const filteredAddresses = {
          legacy: addresses.legacy,
          p2sh: addresses.p2sh,
          bech32: addresses.bech32,
          taproot: addresses.taproot
        };
        console.log('Wallet imported (public info only):', filteredAddresses)


        window.walletKeyPair = walletKeyPair;
        window.walletPublicKey = walletPublicKey;
        window.bech32Address = bech32Address;
        window.rpc = rpc;
        window.balance = balance;
        window.taprootAddress = taprootAddress;
        console.log("✅ Variables messagerie exposées:", bech32Address);

        $('privateKeyWIF').classList.add('blurred-input');

        const revealWifInput = $('revealWifInput');
        if (revealWifInput) {
          revealWifInput.onclick = () => {
            revealWifInput.disabled = true;
            $('privateKeyWIF').classList.remove('blurred-input');
            setTimeout(() => {
              $('privateKeyWIF').classList.add('blurred-input');
              revealWifInput.disabled = false;
            }, 10000);
          };
        }

        const copyBech32Addr = $('copyBech32Addr');
        if (copyBech32Addr) copyBech32Addr.onclick = () => copyToClipboard('bech32Address');

        const copyTaprootAddr = $('copyTaprootAddr');
        if (copyTaprootAddr && importType === 'hd') copyTaprootAddr.onclick = () => copyToClipboard('taprootAddress');


        const debitTypeSelect = $('debitAddressType');
        if (debitTypeSelect) {

          debitTypeSelect.innerHTML = '';


          if (importType === 'single') {
            const bech32Option = document.createElement('option');
            bech32Option.value = 'bech32';
            bech32Option.textContent = 'bech32';
            debitTypeSelect.appendChild(bech32Option);
          } else if (importType === 'hd') {

            const bech32Option = document.createElement('option');
            bech32Option.value = 'bech32';
            bech32Option.textContent = 'bech32';
            debitTypeSelect.appendChild(bech32Option);

            const taprootOption = document.createElement('option');
            taprootOption.value = 'p2tr';
            taprootOption.textContent = 'bech32m';
            debitTypeSelect.appendChild(taprootOption);
          }
        }

        const consolidateContainer = document.querySelector('.consolidate-container');
        if (!consolidateContainer) {
          console.error('Consolidate container not found');
          return;
        }
        if (!consolidateButtonInjected) {
          const consolidateButton = document.createElement('button');
          consolidateButton.id = 'consolidateButton';
          consolidateButton.className = 'consolidate-button';
          consolidateButton.textContent = i18next.t('send_section.consolidate_button');
          consolidateContainer.appendChild(consolidateButton);
          consolidateButton.onclick = () => consolidateUtxos();
          consolidateButtonInjected = true;
          console.log('Consolidate button injected');
        } else {
          const existingButton = $('consolidateButton');
          existingButton.textContent = i18next.t('send_section.consolidate_button');
          existingButton.onclick = () => consolidateUtxos();
          console.log('Consolidate button already present, event attached');
        }


        const maxButton = $('maxButton');
        if (maxButton) {
          maxButton.onclick = async () => {
            const dest = $('destinationAddress').value.trim();
            if (!dest) return alert(i18next.t('errors.enter_destination_first'));

            try {
              showLoadingSpinner();
              const sourceType = $('debitAddressType').value;
              const sourceAddress = sourceType === 'p2tr' ? taprootAddress : bech32Address;
              const ins = await utxos(sourceAddress);
              const workingIns = await filterOpReturnUtxos(ins);
              if (!workingIns.length) {
                hideLoadingSpinner();
                return alert(i18next.t('errors.no_utxo_available_max'));
              }


              workingIns.sort((a, b) => b.amount - a.amount);
              const selectedIns = workingIns;

              let total = selectedIns.reduce((sum, u) => sum + Math.round(u.amount * 1e8), 0);


              const destScriptType = getAddressType(dest);
              const fees = feeForVsize(estimateVBytesMixed(selectedIns, [destScriptType]));

              const maxAmount = (total - fees) / 1e8;
              const maxSats = Math.round((total - fees));
              const dust = getDustThreshold(destScriptType);
              if (maxSats < dust) {
                hideLoadingSpinner();
                return alert(i18next.t('errors.max_insufficient_amount'));
              }
              hideLoadingSpinner();

              if (maxAmount <= 0) {
                return alert(i18next.t('errors.max_insufficient_amount'));
              }

              $('amountNito').value = maxAmount.toFixed(8);
              $('feeNito').value = (fees / 1e8).toFixed(8);

              alert(i18next.t('max_button.info', {
                amount: maxAmount.toFixed(8),
                fees: (fees / 1e8).toFixed(8),
                utxos: selectedIns.length
              }));
            } catch (e) {
              hideLoadingSpinner();
              alert(`Erreur: ${e.message}`);
            }
          };
        }
      } catch (e) {
        alert(i18next.t('errors.import_error', { message: e.message }));
        console.error('Import error:', e);
      }
    };

    $('refreshBalanceButton').onclick = async () => {
      updateLastActionTime();
      if (!walletAddress) return alert(i18next.t('errors.import_first'));
      try {
        const bech32Balance = await balance(bech32Address);
        let taprootBalance = 0;
        let balanceDisplay = `Bech32: ${bech32Balance.toFixed(8)} `;

        if (importType === 'hd') {
          taprootBalance = await balance(taprootAddress);
          balanceDisplay = `Bech32: ${bech32Balance.toFixed(8)} | Bech32m (Taproot): ${taprootBalance.toFixed(8)} `;
        }

        if (!await validateAddress(bech32Address) || (importType === 'hd' && !await validateAddress(taprootAddress))) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        let addressDisplay = `
          Bech32: <span id="bech32Address">${bech32Address}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (${bech32Balance.toFixed(8)} )
        `;

        if (importType === 'hd') {
          addressDisplay += `<br>Bech32m (Taproot): <span id="taprootAddress">${taprootAddress}</span> <button class="copy-btn" id="copyTaprootAddr">📋</button> (${taprootBalance.toFixed(8)} )`;
        }

        $('walletAddress').innerHTML = DOMPurify.sanitize(addressDisplay);
        $('walletBalance').innerHTML = balanceDisplay;

        const copyBech32Addr = $('copyBech32Addr');
        if (copyBech32Addr) copyBech32Addr.onclick = () => copyToClipboard('bech32Address');

        const copyTaprootAddr = $('copyTaprootAddr');
        if (copyTaprootAddr && importType === 'hd') copyTaprootAddr.onclick = () => copyToClipboard('taprootAddress');
      } catch (e) {
        alert(i18next.t('errors.refresh_error', { message: e.message }));
        console.error('Refresh error:', e);
      }
    };

    $('prepareTxButton').onclick = async () => {
      updateLastActionTime();
      try {
        const dest = $('destinationAddress').value.trim();
        const amt = parseFloat($('amountNito').value);
        if (!dest || isNaN(amt) || amt <= 0) {
          alert(i18next.t('errors.invalid_fields'));
          return;
        }
        try {
          bitcoin.address.toOutputScript(dest, NITO_NETWORK);
        } catch (e) {
          alert(i18next.t('errors.invalid_address'));
          return;
        }

        showLoadingSpinner();

        const sourceType = $('debitAddressType').value;
        const destType = getAddressType(dest);
        let hex;

        try {
          let signerAddress;
          let signerPublicKey;
          let signerKeyPair;

          if (sourceType === 'p2tr') {
            signerAddress = taprootAddress;
            signerPublicKey = taprootPublicKey;
            signerKeyPair = taprootKeyPair;
          } else if (sourceType === 'bech32') {
            signerAddress = bech32Address;
            signerPublicKey = walletPublicKey;
            signerKeyPair = walletKeyPair;
          } else {
            signerAddress = sourceType === 'legacy' ? legacyAddress : sourceType === 'p2sh' ? p2shAddress : bech32Address;
            signerPublicKey = walletPublicKey;
            signerKeyPair = walletKeyPair;
          }

          const originalWalletAddress = walletAddress;
          const originalWalletPublicKey = walletPublicKey;
          const originalWalletKeyPair = walletKeyPair;

          walletAddress = signerAddress;
          walletPublicKey = signerPublicKey;
          walletKeyPair = signerKeyPair;

          let result;
          try {
            if (sourceType === 'bech32') {
              result = await signTx(dest, amt);
            } else {
              result = await signTxWithPSBT(dest, amt);
            }
          } finally {
            walletAddress = originalWalletAddress;
            walletPublicKey = originalWalletPublicKey;
            walletKeyPair = originalWalletKeyPair;
          }

          hex = result.hex;
          $('feeNito').value = result.actualFees.toFixed(8);

          hideLoadingSpinner();
          $('signedTx').textContent = hex;
          $('txHexContainer').style.display = 'block';
          alert(i18next.t('OK.transaction_prepared') + ` Fee: ${result.actualFees.toFixed(8)} NITO`);
        } catch (e) {
          hideLoadingSpinner();
          throw e;
        }
      } catch (e) {
        hideLoadingSpinner();
        alert(i18next.t('errors.transaction_error', { message: e.message }));
        console.error('Transaction preparation error:', e);
      }
    };

    $('broadcastTxButton').onclick = async () => {
      updateLastActionTime();
      const hex = $('signedTx').textContent.trim();
      if (!hex) return alert(i18next.t('errors.no_transaction'));

      try {
        showLoadingSpinner();
        const txid = await rpc('sendrawtransaction', [hex]);
        hideLoadingSpinner();

        await showSuccessPopup(txid);
        $('destinationAddress').value = '';
        $('amountNito').value = '';
        $('signedTx').textContent = '';
        $('txHexContainer').style.display = 'none';
        setTimeout(() => $('refreshBalanceButton').click(), 3000);
      } catch (e) {
        hideLoadingSpinner();
        alert(i18next.t('errors.broadcast_error', { message: e.message }));
        console.error('Broadcast error:', e, 'Transaction hex:', hex);
      }
    };

    $('cancelTxButton').onclick = () => {
      updateLastActionTime();
      ['destinationAddress', 'amountNito'].forEach(id => $(id).value = '');
      ['signedTx'].forEach(id => $(id).textContent = '');
      $('txHexContainer').style.display = 'none';
    };
  } catch (e) {
    alert(i18next.t('errors.node_connection', { message: e.message }));
    console.error('Connection error:', e);
  }
});
window.showSuccessPopup = showSuccessPopup;
