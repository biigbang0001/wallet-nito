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
// --- Global TX tracking for final popup ---
let lastTxid = null; // global fallback for UI handlers
window._lastConsolidationTxid = null; // canonical global

// --- Success popup singleton + timer cleanup (shown only for the final TX) ---
let _successPopupEl = null;
let _successPopupTimer = null;


// Network Configuration
const NITO_NETWORK = {
  messagePrefix: '\x18NITO Signed Message:\n',
  bech32: 'nito',
  bip32: { public: 0x0488B21E, private: 0x0488ADE4 },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80
};

// Constants
const NODE_URL = '/api/';
const RPC_DEBUG = false;
const DUST_RELAY_AMOUNT = 3000;
const DUST_AMOUNT = {
  p2pkh: 546,
  p2wpkh: 294,
  p2sh: 540,
  p2tr: 330
};
const MIN_CONSOLIDATION_FEE = 0.00005;
const MAX_UTXOS_PER_BATCH = 500;
const HD_START_RANGE = 512;
const HD_MAX_RANGE = 50000;
const HD_RANGE_SAFETY = 16;
const HD_SCAN_CHUNK = 50;
const HD_SCAN_MAX_CHUNKS = 40;

// ECC Setup
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
const ECPair = ECPairFactory(wrappedEcc);

/**
 * Secure key storage and management
 */
class SecureKeyManager {
  constructor() {
    this.#sessionKey = null;
    this.#encryptedData = new Map();
    this.#lastAccess = Date.now();
    this.#setupAutoCleanup();
  }

  #sessionKey = null;
  #encryptedData = new Map();
  #lastAccess = null;
  #cleanupTimer = null;

  #setupAutoCleanup() {
    if (this.#cleanupTimer) clearTimeout(this.#cleanupTimer);
    this.#cleanupTimer = setTimeout(() => {
      this.clearAll();
    }, 600000); // 10 minutes
  }

  #updateAccess() {
    this.#lastAccess = Date.now();
    this.#setupAutoCleanup();
  }

  async #generateSessionKey() {
    if (!this.#sessionKey) {
      const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
      this.#sessionKey = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );
    }
    return this.#sessionKey;
  }

  async #encrypt(data) {
    const key = await this.#generateSessionKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    return { iv, data: new Uint8Array(encrypted) };
  }

  async #decrypt(encryptedData) {
    const key = await this.#generateSessionKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: encryptedData.iv },
      key,
      encryptedData.data
    );
    const decoded = new TextDecoder().decode(decrypted);
    return JSON.parse(decoded);
  }

  async storeKey(id, keyData) {
    this.#updateAccess();
    const encrypted = await this.#encrypt(keyData);
    this.#encryptedData.set(id, encrypted);
  }

  async getKey(id) {
    this.#updateAccess();
    const encrypted = this.#encryptedData.get(id);
    if (!encrypted) return null;
    return await this.#decrypt(encrypted);
  }

  clearAll() {
    this.#encryptedData.clear();
    this.#sessionKey = null;
    if (this.#cleanupTimer) {
      clearTimeout(this.#cleanupTimer);
      this.#cleanupTimer = null;
    }
  }

  hasKey(id) {
    return this.#encryptedData.has(id);
  }
}

/**
 * Network fee estimation and management
 */
class FeeManager {
  constructor() {
    this.minFeeRate = 0.00001;
    this.dynamicFeeRate = null;
    this.mempoolMinFee = null;
    this.relayFee = null;
  }

  async initNetworkParams() {
    try {
      const feeInfo = await rpc('estimatesmartfee', [6]);
      const rawFeeRate = (feeInfo && typeof feeInfo.feerate === 'number') ? feeInfo.feerate : this.minFeeRate;
      this.dynamicFeeRate = Math.max(rawFeeRate, this.minFeeRate);

      try {
        const mem = await rpc('getmempoolinfo', []);
        if (mem && typeof mem.mempoolminfee === 'number') this.mempoolMinFee = mem.mempoolminfee;
      } catch (e) {
        console.warn('getmempoolinfo failed:', e?.message || e);
      }

      try {
        const net = await rpc('getnetworkinfo', []);
        if (net && typeof net.relayfee === 'number') this.relayFee = net.relayfee;
      } catch (e) {
        console.warn('getnetworkinfo failed:', e?.message || e);
      }

      console.log('Fee params', { 
        DYNAMIC_FEE_RATE: this.dynamicFeeRate, 
        MEMPOOL_MIN_FEE: this.mempoolMinFee, 
        RELAY_FEE: this.relayFee 
      });
    } catch (e) {
      console.error('initNetworkParams failed:', e);
    }
  }

  getEffectiveFeeRate() {
    const dyn = (typeof this.dynamicFeeRate === 'number' && !isNaN(this.dynamicFeeRate)) ? this.dynamicFeeRate : 0;
    const mem = (typeof this.mempoolMinFee === 'number' && !isNaN(this.mempoolMinFee)) ? this.mempoolMinFee : 0;
    const rel = (typeof this.relayFee === 'number' && !isNaN(this.relayFee)) ? this.relayFee : 0;
    return Math.max(dyn, mem, rel, this.minFeeRate);
  }

  calculateFeeForVsize(vbytes) {
    const rate = this.getEffectiveFeeRate();
    return Math.ceil(vbytes * (rate * 1.2 * 1e8) / 1000);
  }

  getDustThreshold(scriptType) {
    return DUST_AMOUNT[scriptType] || DUST_AMOUNT.p2sh;
  }

  getInputVBytes(type) {
    const inputSizes = { p2pkh: 148, p2wpkh: 68, p2sh: 91, p2tr: 57.5 };
    return inputSizes[type] || inputSizes.p2wpkh;
  }

  getOutputVBytes(type) {
    const outputSizes = { p2pkh: 34, p2wpkh: 31, p2sh: 32, p2tr: 43 };
    return outputSizes[type] || outputSizes.p2wpkh;
  }

  estimateVBytes(inputType, numInputs, outputTypesArray) {
    const overhead = 10;
    const inSize = this.getInputVBytes(inputType) * numInputs;
    const outSize = (outputTypesArray || []).reduce((s, t) => s + this.getOutputVBytes(t), 0);
    return overhead + inSize + outSize;
  }

  estimateVBytesMixed(inputs, outputTypes) {
    const overhead = 10;
    const inSize = inputs.reduce((s, u) => s + this.getInputVBytes(u.scriptType), 0);
    const outSize = (outputTypes || []).reduce((s, t) => s + this.getOutputVBytes(t), 0);
    return overhead + inSize + outSize;
  }

  estimateFeeWithChange(totalSats, targetSats, inputType, numInputs, destType, changeType) {
    const dustChange = this.getDustThreshold((changeType === 'p2tr') ? 'p2tr' : 'p2wpkh');
    const withChangeVBytes = this.estimateVBytes(inputType, numInputs, [destType, changeType || 'p2wpkh']);
    const withChangeFee = this.calculateFeeForVsize(withChangeVBytes);
    const change = totalSats - targetSats - withChangeFee;
    
    if (change >= dustChange) {
      return { vbytes: withChangeVBytes, fee: withChangeFee, outputs: [destType, changeType || 'p2wpkh'], changeSats: change };
    }

    const noChangeVBytes = this.estimateVBytes(inputType, numInputs, [destType]);
    const noChangeFee = this.calculateFeeForVsize(noChangeVBytes);
    return { vbytes: noChangeVBytes, fee: noChangeFee, outputs: [destType], changeSats: 0 };
  }

  estimateFeeWithChangeMixed(selectedIns, targetSats, destType, changeType) {
    const dustChange = this.getDustThreshold((changeType === 'p2tr') ? 'p2tr' : 'p2wpkh');
    const withChangeVBytes = this.estimateVBytesMixed(selectedIns, [destType, changeType || 'p2wpkh']);
    const withChangeFee = this.calculateFeeForVsize(withChangeVBytes);
    const totalSats = selectedIns.reduce((s, u) => s + Math.round((u.amount || 0) * 1e8), 0);
    const change = totalSats - targetSats - withChangeFee;
    
    if (change >= dustChange) {
      return { vbytes: withChangeVBytes, fee: withChangeFee, outputs: [destType, changeType || 'p2wpkh'], changeSats: change };
    }
    
    const noChangeVBytes = this.estimateVBytesMixed(selectedIns, [destType]);
    const noChangeFee = this.calculateFeeForVsize(noChangeVBytes);
    return { vbytes: noChangeVBytes, fee: noChangeFee, outputs: [destType], changeSats: 0 };
  }
}

/**
 * Bitcoin address utilities
 */
class AddressManager {
  static getAddressType(addr) {
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

  static detectScriptType(scriptPubKey) {
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

  static async validateAddress(address) {
    try {
      const result = await rpc('validateaddress', [address]);
      return result.isvalid;
    } catch (e) {
      console.error('Error validating address:', e);
      return false;
    }
  }

  static getP2SHAddress(pubkeyBuffer) {
    try {
      const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
      const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
      return { address: p2sh.address, redeemScript: p2wpkh.output };
    } catch (e) {
      console.error('Error converting to P2SH:', e);
      throw e;
    }
  }
}

/**
 * Taproot utilities
 */
class TaprootUtils {
  static toXOnly(pubkey) {
    return Buffer.from(pubkey.slice(1, 33));
  }

  static tapTweakHash(pubKey, h = Buffer.alloc(0)) {
    return bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([TaprootUtils.toXOnly(pubKey), h]));
  }

  static tweakSigner(signer, opts = {}) {
    let privateKey = Uint8Array.from(signer.privateKey);
    const publicKey = Uint8Array.from(signer.publicKey);
    if (publicKey[0] === 3) {
      privateKey = wrappedEcc.privateNegate(privateKey);
    }
    const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
    const tweak = Uint8Array.from(TaprootUtils.tapTweakHash(signer.publicKey, tweakHash));
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
}

/**
 * HD Wallet management
 */
class HDWalletManager {
  constructor(keyManager) {
    this.keyManager = keyManager;
    this.hdWallet = null;
    this.currentMnemonic = null;
  }

  generateMnemonic(wordCount = 12) {
    try {
      const entropyBits = wordCount === 24 ? 256 : 128;
      const entropyBytes = entropyBits / 8;
      const entropy = window.crypto.getRandomValues(new Uint8Array(entropyBytes));
      const entropyHex = Array.from(entropy).map(x => x.toString(16).padStart(2, '0')).join('');
      return bip39.entropyToMnemonic(entropyHex);
    } catch (e) {
      console.error('Error generating mnemonic:', e);
      throw new Error(i18next.t('errors.mnemonic_generation_error'));
    }
  }

  async importHDWallet(seedOrXprv, passphrase = '') {
    try {
      let seed;
      
      if (seedOrXprv.startsWith('xprv')) {
        this.hdWallet = bip32.fromBase58(seedOrXprv);
        this.currentMnemonic = null;
      } else {
        const mnemonic = seedOrXprv.trim();
        if (!bip39.validateMnemonic(mnemonic)) {
          throw new Error(i18next.t('errors.invalid_mnemonic'));
        }
        seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        this.hdWallet = bip32.fromSeed(seed);
        this.currentMnemonic = mnemonic;
      }

      const addresses = this.deriveMainAddresses();
      
      // Store encrypted keys
      await this.keyManager.storeKey('hdWallet', {
        masterKey: this.hdWallet.toBase58(),
        mnemonic: this.currentMnemonic
      });
      
      await this.keyManager.storeKey('bech32KeyPair', {
        privateKey: addresses.keyPair.privateKey.toString('hex'),
        publicKey: addresses.publicKey.toString('hex')
      });
      
      if (addresses.taprootKeyPair) {
        await this.keyManager.storeKey('taprootKeyPair', {
          privateKey: addresses.taprootKeyPair.privateKey.toString('hex'),
          publicKey: addresses.taprootPublicKey.toString('hex')
        });
      }

      return addresses;
    } catch (e) {
      console.error('Error importing HD:', e);
      throw new Error(i18next.t('errors.hd_import_error', { message: e.message }));
    }
  }

  deriveMainAddresses() {
    if (!this.hdWallet) throw new Error('HD wallet not initialized');

    const bech32Node = this.hdWallet.derivePath("m/84'/0'/0'/0/0");
    const legacyNode = this.hdWallet.derivePath("m/44'/0'/0'/0/0");
    const p2shNode = this.hdWallet.derivePath("m/49'/0'/0'/0/0");
    const taprootNode = this.hdWallet.derivePath("m/86'/0'/0'/0/0");

    const pubkey = Buffer.from(bech32Node.publicKey);
    const keyPair = ECPair.fromPrivateKey(bech32Node.privateKey, { network: NITO_NETWORK });

    const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(legacyNode.publicKey), network: NITO_NETWORK });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkey, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({
      redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }),
      network: NITO_NETWORK
    });

    const tapInternalPubkey = TaprootUtils.toXOnly(taprootNode.publicKey);
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
      hdMasterKey: this.hdWallet.toBase58(),
      mnemonic: this.currentMnemonic
    };
  }

  getHdAccountNode(family) {
    if (!this.hdWallet) throw new Error('HD wallet not initialized');
    if (family === 'legacy') return this.hdWallet.derivePath("m/44'/0'/0'");
    if (family === 'p2sh') return this.hdWallet.derivePath("m/49'/0'/0'");
    if (family === 'bech32') return this.hdWallet.derivePath("m/84'/0'/0'");
    if (family === 'taproot') return this.hdWallet.derivePath("m/86'/0'/0'");
    throw new Error('Unknown family for HD');
  }

  deriveKeyFor(family, branch, index) {
    const account = this.getHdAccountNode(family);
    const node = account.derive(branch).derive(index);
    const keyPair = ECPair.fromPrivateKey(node.privateKey, { network: NITO_NETWORK });
    const pub = Buffer.from(node.publicKey);
    
    if (family === 'taproot') {
      return { keyPair, tapInternalKey: TaprootUtils.toXOnly(pub), scriptType: 'p2tr' };
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
}

/**
 * RPC and network utilities
 */
const RAW_TX_CACHE = new Map();

// --- Timing helpers ---
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function sleepJitter(baseMs = 1, maxJitterMs = 300, active = false) {
  const extra = active ? Math.floor(Math.random() * (maxJitterMs + 1)) : 0;
  await sleep(baseMs + extra);
}


// Methods that should NOT use 2s backoff on HTTP 503 (Service Unavailable)
const NO_503_BACKOFF = new Set(['getrawmempool','getrawtransaction','getmempoolinfo']);
async function rpc(method, params) {
  // helper: pause in ms
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  const conflictMethods = ['scantxoutset'];

  // Common request executor returning result or null (to signal retry)
  const doRequest = async () => {
    const res = await fetch(NODE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
    });

    // Immediate retry for HTTP 503 from server
    if (res && res.status === 503) {
      if (NO_503_BACKOFF.has(method)) {
        console.warn('⚠️ 503 (Service Unavailable) pour', method, '- retry immédiat sans délai');
        return null; // retry loop continues without 2s sleep
      }
      console.warn('⏳ 503 erreur waiting, retry in 2s...')
      await sleep(2000);
      return null; // tell caller to retry
    }

    const text = await res.text();

    if (res && res.status == 500 && text && text.includes('Scan already in progress')) {
      console.warn('⏳ scantxoutset busy (500). Nouveau try dans 2s…');
      await sleep(2000);
      return null;
    }

    if (method !== 'getnetworkinfo' && method !== 'estimatesmartfee') {
      if (RPC_DEBUG) console.log('RPC raw response:', text);
    }

    if (!res.ok) throw new Error(`HTTP Error: ${res.status} - ${text}`);

    const data = JSON.parse(text);
    if (data.error) throw new Error(data.error.message);

    return data.result;
  };

  // Some methods on some nodes are already looped; we keep structure but unify 503 handling
  if (conflictMethods.includes(method)) {
    while (true) {
      try {
        const out = await doRequest();
        if (out === null) continue; // retry after 503 wait
        return out;
      } catch (e) {
        const msg = String((e && e.message) || e || '');
        if (msg.includes('503') || msg.includes('Scan already in progress') || msg.includes('code":-8')) {
          if (msg.includes('503') && NO_503_BACKOFF.has(method)) {
            console.warn('⚠️ 503 (Service Unavailable) pour', method, '- retry immédiat sans délai');
            continue;
          }
          console.warn('⏳ 503 erreur waiting, retry in 2s...')
          await sleep(2000);
          continue;
        }
        console.error('RPC Error:', method, e);
        throw e;
      }
    }
  } else {
    while (true) {
      try {
        const out = await doRequest();
        if (out === null) continue; // retry after 503 wait
        return out;
      } catch (e) {
        const msg = String((e && e.message) || e || '');
        if (msg.includes('503') || msg.includes('Scan already in progress') || msg.includes('code":-8')) {
          if (msg.includes('503') && NO_503_BACKOFF.has(method)) {
            console.warn('⚠️ 503 (Service Unavailable) pour', method, '- retry immédiat sans délai');
            continue;
          }
          console.warn('⏳ 503 erreur waiting, retry in 2s...')
          await sleep(2000);
          continue;
        }
        console.error('RPC Error:', method, e);
        throw e;
      }
    }
  }
}


async function fetchRawTxHex(txid) {
  if (RAW_TX_CACHE.has(txid)) return RAW_TX_CACHE.get(txid);
  const raw = await rpc('getrawtransaction', [txid, true]);
  const hex = raw && raw.hex ? raw.hex : null;
  if (!hex) throw new Error(`rawtx not found for ${txid}`);
  RAW_TX_CACHE.set(txid, hex);
  return hex;
}

/**
 * Global wallet state management
 */
class WalletState {
  constructor() {
    this.keyManager = new SecureKeyManager();
    this.feeManager = new FeeManager();
    this.hdManager = new HDWalletManager(this.keyManager);
    this.reset();
  }

  reset() {
    this.walletAddress = '';
    this.legacyAddress = '';
    this.p2shAddress = '';
    this.bech32Address = '';
    this.taprootAddress = '';
    this.importType = '';
    this.lastActionTime = null;
    this.inactivityTimeout = null;
    this.timerInterval = null;
    this.consolidateButtonInjected = false;
  }

  updateLastActionTime() {
    this.lastActionTime = Date.now();
    if (this.inactivityTimeout) clearTimeout(this.inactivityTimeout);
    this.inactivityTimeout = setTimeout(() => this.clearSensitiveData(), 600000);
  }

  clearSensitiveData() {
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

  async getWalletKeyPair() {
    const keyData = await this.keyManager.getKey('bech32KeyPair');
    if (!keyData) return null;
    return ECPair.fromPrivateKey(Buffer.from(keyData.privateKey, 'hex'), { network: NITO_NETWORK });
  }

  async getWalletPublicKey() {
    const keyData = await this.keyManager.getKey('bech32KeyPair');
    if (!keyData) return null;
    return Buffer.from(keyData.publicKey, 'hex');
  }

  async getTaprootKeyPair() {
    const keyData = await this.keyManager.getKey('taprootKeyPair');
    if (!keyData) return null;
    return ECPair.fromPrivateKey(Buffer.from(keyData.privateKey, 'hex'), { network: NITO_NETWORK });
  }

  async getTaprootPublicKey() {
    const keyData = await this.keyManager.getKey('taprootKeyPair');
    if (!keyData) return null;
    return Buffer.from(keyData.publicKey, 'hex');
  }
}

// Global instances
const walletState = new WalletState();
const feeManager = walletState.feeManager;
const hdManager = walletState.hdManager;

/**
 * UTXO scanning and management
 */
class UTXOScanner {
  constructor(hdManager) {
    this.hdManager = hdManager;
  }

  async scanBranch(family, branch, startRange = HD_START_RANGE) {
    const descriptor = this.makeFamilyDescriptor(family, branch);
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
      if (!unspents.length && current > startRange) break;

      let map = null;
      for (const u of unspents) {
        const key = `${u.txid}:${u.vout}`;
        if (seen.has(key)) continue;
        seen.add(key);

        let branchIdx = branch;
        let index = null;
        if (u.desc) {
          const parsed = this.parseDescBranchIndex(u.desc);
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
          scriptType: AddressManager.detectScriptType(u.scriptPubKey)
        };

        if (index !== null) {
          const keyInfo = this.hdManager.deriveKeyFor(family, branchIdx, index);
          enriched.keyPair = keyInfo.keyPair;
          if (keyInfo.tapInternalKey) enriched.tapInternalKey = keyInfo.tapInternalKey;
        } else {
          if (!map) map = this.prederiveMapForRange(family, branch, 0, current);
          const info = map[(u.scriptPubKey || '').toLowerCase()];
          if (info) {
            enriched.keyPair = info.keyPair;
            if (info.tapInternalKey) enriched.tapInternalKey = info.tapInternalKey;
            if (info.redeemScript) enriched.redeemScript = info.redeemScript;
          }
        }
        
        if (index !== null && index > maxIndex) maxIndex = index;
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

  parseDescBranchIndex(desc) {
    try {
      const m = desc.match(/\/(0|1)\/(\d+)\)?/);
      if (!m) return null;
      return { branch: parseInt(m[1], 10), index: parseInt(m[2], 10) };
    } catch (_) { 
      return null; 
    }
  }

  prederiveMapForRange(family, branch, start, count) {
    const byScriptHex = {};
    const network = NITO_NETWORK;
    const account = this.hdManager.getHdAccountNode(family);
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
        const internal = TaprootUtils.toXOnly(pub);
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

  makeFamilyDescriptor(family, branch) {
    const xpub = this.xpubForFamily(family);
    if (family === 'p2sh') return `sh(wpkh(${xpub}/${branch}/*))`;
    const prefix = this.familyToDescriptorPrefix(family);
    return `${prefix}(${xpub}/${branch}/*)`;
  }

  xpubForFamily(family) {
    const acct = this.hdManager.getHdAccountNode(family).neutered();
    return acct.toBase58();
  }

  familyToDescriptorPrefix(family) {
    if (family === 'bech32') return 'wpkh';
    if (family === 'taproot') return 'tr';
    if (family === 'legacy') return 'pkh';
    throw new Error('Unknown family');
  }

  async scanHdUtxosForFamilyDescriptor(family) {
    try {
      const res0 = await this.scanBranch(family, 0, HD_START_RANGE);
      const res1 = await this.scanBranch(family, 1, HD_START_RANGE);
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
      return await this.scanHdUtxosForFamily(family);
    }
  }

  deriveHdChunk(family, start, count) {
    if (!this.hdManager.hdWallet) throw new Error('HD wallet not initialized');
    const byScriptHex = {};
    const descriptors = [];
    const network = NITO_NETWORK;

    if (family === 'bech32') {
      const account = this.hdManager.hdWallet.derivePath("m/84'/0'/0'");
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
      const account = this.hdManager.hdWallet.derivePath("m/86'/0'/0'");
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          if (!node.privateKey) continue;
          const internal = TaprootUtils.toXOnly(node.publicKey);
          const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
          const pay = bitcoin.payments.p2tr({ internalPubkey: internal, network });
          if (!pay.address || !pay.output) continue;
          const scriptHex = pay.output.toString('hex').toLowerCase();
          byScriptHex[scriptHex] = { keyPair, scriptType: 'p2tr', tapInternalKey: internal };
          descriptors.push(`addr(${pay.address})`);
        }
      }
    } else if (family === 'legacy' || family === 'p2sh') {
      const account = this.hdManager.getHdAccountNode(family);
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

  async scanHdUtxosForFamily(family) {
    const allUtxos = [];
    const seen = new Set();

    for (let chunk = 0; chunk < HD_SCAN_MAX_CHUNKS; chunk++) {
      const start = chunk * HD_SCAN_CHUNK;
      const { descriptors, byScriptHex } = this.deriveHdChunk(family, start, HD_SCAN_CHUNK);
      if (!descriptors.length) break;

      let scan;
      try {
        scan = await rpc('scantxoutset', ['start', descriptors]);
      } catch (e) {
        console.error('scantxoutset failed for HD scan chunk', { family, start }, e);
        break;
      }
      
      const unspents = (scan && scan.unspents) ? scan.unspents : [];
      if (!unspents.length && chunk > 0) break;

      for (const u of unspents) {
        if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) continue;
        const scriptHex = u.scriptPubKey.toLowerCase();
        const keyInfo = byScriptHex[scriptHex];
        const key = `${u.txid}:${u.vout}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const scriptType = AddressManager.detectScriptType(u.scriptPubKey);
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

  async utxosAllForBech32() {
    const families = ['bech32', 'p2sh', 'legacy'];
    const parts = [];
    
    for (const fam of families) {
      try { 
        parts.push(await this.scanHdUtxosForFamilyDescriptor(fam)); 
      } catch (e) {
        parts.push(await this.scanHdUtxosForFamily(fam));
      }
    }
    
    const seen = new Set();
    const merged = [];
    for (const arr of parts) {
      for (const u of arr) {
        const k = `${u.txid}:${u.vout}`;
        if (seen.has(k)) continue; 
        seen.add(k);
        merged.push(u);
      }
    }
    return merged;
  }
}

/**
 * Transaction builder and signer
 */
class TransactionBuilder {
  constructor(keyManager, feeManager) {
    this.keyManager = keyManager;
    this.feeManager = feeManager;
  }

  async signTxBatch(to, amt, specificUtxos, isConsolidation = true) {
    const destScriptType = AddressManager.getAddressType(to);
    const target = Math.round(amt * 1e8);

    const selectedIns = [...specificUtxos];
    const est = this.feeManager.estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
    const fees = est.fee;
    const total = selectedIns.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    const change = total - target - fees;
    
    if (change < 0 && !isConsolidation) {
      throw new Error(i18next.t('errors.insufficient_funds'));
    }

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const u of selectedIns) {
      const scriptBuffer = Buffer.from(u.scriptPubKey, 'hex');
      if (u.scriptType === 'p2wpkh') {
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) } });
      } else if (u.scriptType === 'p2sh') {
        const walletPublicKey = await this.keyManager.getKey('bech32KeyPair');
        const redeem = u.redeemScript || bitcoin.payments.p2wpkh({ 
          pubkey: Buffer.from((u.keyPair || Buffer.from(walletPublicKey.publicKey, 'hex')).publicKey), 
          network: NITO_NETWORK 
        }).output;
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) }, redeemScript: redeem });
      } else if (u.scriptType === 'p2pkh') {
        const hex = await fetchRawTxHex(u.txid);
        psbt.addInput({ hash: u.txid, index: u.vout, nonWitnessUtxo: Buffer.from(hex, 'hex') });
      } else if (u.scriptType === 'p2tr') {
        const taprootPublicKey = await walletState.getTaprootPublicKey();
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) }, tapInternalKey: (u.tapInternalKey || taprootPublicKey) });
      } else {
        throw new Error(i18next.t('errors.unsupported_address_type'));
      }
    }

    if (target < this.feeManager.getDustThreshold(destScriptType)) {
      throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: this.feeManager.getDustThreshold(destScriptType) }));
    }
    psbt.addOutput({ address: to, value: target });

    if (change > this.feeManager.getDustThreshold('p2wpkh') && !isConsolidation) {
      psbt.addOutput({ address: walletState.walletAddress, value: change });
    }

    for (let i = 0; i < selectedIns.length; i++) {
      const u = selectedIns[i];
      if (u.scriptType === 'p2tr') {
        const kp = u.keyPair || await walletState.getTaprootKeyPair();
        const tweaked = TaprootUtils.tweakSigner(kp, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
      } else {
        const kp = u.keyPair || await walletState.getWalletKeyPair();
        psbt.signInput(i, kp);
      }
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();
    return { hex, actualFees: fees / 1e8 };
  }

  async signTxWithPSBT(to, amt, isConsolidation = false) {
    walletState.updateLastActionTime();
    const walletKeyPair = await walletState.getWalletKeyPair();
    const walletPublicKey = await walletState.getWalletPublicKey();
    
    if (!walletState.walletAddress || !walletKeyPair || !walletPublicKey) {
      throw Error(i18next.t('errors.import_first'));
    }

    console.log('Starting transaction preparation for:', to, 'Amount:', amt, 'Consolidation:', isConsolidation);

    const ins = await utxos(walletState.walletAddress);
    if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

    const workingIns = isConsolidation ? ins : await filterOpReturnUtxos(ins);
    if (!workingIns.length) throw new Error('No UTXO available (all contain OP_RETURN, please consolidate UTXOs)');

    const sendScriptType = AddressManager.getAddressType(walletState.walletAddress);
    const destScriptType = AddressManager.getAddressType(to);
    console.log('Script type - sender:', sendScriptType, 'destination:', destScriptType);

    const target = Math.round(amt * 1e8);
    workingIns.sort((a, b) => b.amount - a.amount);
    let total = 0;
    const selectedIns = [];

    for (const u of workingIns) {
      selectedIns.push(u);
      total += Math.round(u.amount * 1e8);

      if (!isConsolidation) {
        const _feeEst = this.feeManager.estimateFeeWithChange(total, target, sendScriptType, selectedIns.length, destScriptType, 'p2wpkh');
        const estimatedSize = _feeEst.vbytes;
        const estimatedFees = _feeEst.fee;

        if (total >= target + estimatedFees + this.feeManager.getDustThreshold(sendScriptType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
          break;
        }
      }
    }

    const _feeEst = this.feeManager.estimateFeeWithChange(total, target, sendScriptType, selectedIns.length, destScriptType, 'p2wpkh');
    const txSize = _feeEst.vbytes;
    const inputFee = _feeEst.fee;

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
        const { redeemScript } = AddressManager.getP2SHAddress(walletPublicKey);
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
        const taprootPublicKey = await walletState.getTaprootPublicKey();
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

    if (target < this.feeManager.getDustThreshold(destScriptType)) {
      throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: this.feeManager.getDustThreshold(destScriptType) }));
    }
    psbt.addOutput({ address: to, value: target });

    if (change > this.feeManager.getDustThreshold(sendScriptType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
      psbt.addOutput({ address: walletState.walletAddress, value: change });
    }

    for (let i = 0; i < selectedIns.length; i++) {
      const u = selectedIns[i];
      if (sendScriptType === 'p2tr') {
        const kp = u.keyPair || await walletState.getTaprootKeyPair();
        const tweakedSigner = TaprootUtils.tweakSigner(kp, { network: NITO_NETWORK });
        psbt.signInput(i, tweakedSigner);
      } else {
        const kp = u.keyPair || walletKeyPair;
        psbt.signInput(i, kp);
      }
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();

    console.log('Transaction PSBT hex:', hex, 'TXID:', tx.getId());
    return { hex, actualFees: fees / 1e8 };
  }

  async signTx(to, amt, isConsolidation = false) {
    walletState.updateLastActionTime();
    const walletKeyPair = await walletState.getWalletKeyPair();
    const walletPublicKey = await walletState.getWalletPublicKey();
    
    if (!walletState.walletAddress || !walletKeyPair || !walletPublicKey) {
      throw Error(i18next.t('errors.import_first'));
    }

    const ins = await utxos(walletState.walletAddress);
    if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

    const workingIns = isConsolidation ? ins : await filterOpReturnUtxos(ins);
    if (!workingIns.length) throw new Error(i18next.t('errors.utxo_opreturn_consolidate'));

    const destScriptType = AddressManager.getAddressType(to);
    const target = Math.round(amt * 1e8);

    workingIns.sort((a, b) => b.amount - a.amount);
    const selectedIns = [];
    let total = 0;
    
    for (const u of workingIns) {
      selectedIns.push(u);
      total += Math.round(u.amount * 1e8);
      if (!isConsolidation) {
        const est = this.feeManager.estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
        if (total >= target + est.fee + this.feeManager.getDustThreshold('p2wpkh')) break;
      }
    }

    const est = this.feeManager.estimateFeeWithChangeMixed(selectedIns, target, destScriptType, 'p2wpkh');
    const fees = est.fee;
    const change = selectedIns.reduce((s, u) => s + Math.round(u.amount * 1e8), 0) - target - fees;
    if (change < 0) throw new Error(i18next.t('errors.insufficient_funds'));

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const u of selectedIns) {
      const scriptBuffer = Buffer.from(u.scriptPubKey, 'hex');
      if (u.scriptType === 'p2wpkh') {
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) } });
      } else if (u.scriptType === 'p2sh') {
        const redeem = u.redeemScript || bitcoin.payments.p2wpkh({ pubkey: Buffer.from((u.keyPair || walletKeyPair).publicKey), network: NITO_NETWORK }).output;
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) }, redeemScript: redeem });
      } else if (u.scriptType === 'p2pkh') {
        const hex = await fetchRawTxHex(u.txid);
        psbt.addInput({ hash: u.txid, index: u.vout, nonWitnessUtxo: Buffer.from(hex, 'hex') });
      } else if (u.scriptType === 'p2tr') {
        const taprootPublicKey = await walletState.getTaprootPublicKey();
        psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: scriptBuffer, value: Math.round(u.amount * 1e8) }, tapInternalKey: (u.tapInternalKey || taprootPublicKey) });
      } else {
        throw new Error(i18next.t('errors.unsupported_address_type'));
      }
    }

    if (target < this.feeManager.getDustThreshold(destScriptType)) {
      throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: this.feeManager.getDustThreshold(destScriptType) }));
    }
    psbt.addOutput({ address: to, value: target });

    if (change > this.feeManager.getDustThreshold('p2wpkh') && !isConsolidation) {
      psbt.addOutput({ address: walletState.walletAddress, value: change });
    }

    for (let i = 0; i < selectedIns.length; i++) {
      const u = selectedIns[i];
      if (u.scriptType === 'p2tr') {
        const kp = u.keyPair || await walletState.getTaprootKeyPair();
        const tweaked = TaprootUtils.tweakSigner(kp, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
      } else {
        const kp = u.keyPair || walletKeyPair;
        psbt.signInput(i, kp);
      }
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();
    return { hex, actualFees: fees / 1e8 };
  }
}

/**
 * API utilities for external services
 */
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

// Initialize global scanner and transaction builder
const utxoScanner = new UTXOScanner(hdManager);
const transactionBuilder = new TransactionBuilder(walletState.keyManager, feeManager);

// Backward compatibility functions
async function filterOpReturnUtxos(utxos) {
  const filteredUtxos = utxos.filter(utxo => utxo.amount >= 0.00005);
  console.log(`UTXOs filtered: ${filteredUtxos.length}/${utxos.length} (> 0.00005 NITO)`);
  return filteredUtxos;
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

function importWIF(wif) {
  try {
    let kp = ECPair.fromWIF(wif, NITO_NETWORK);
    if (!kp.publicKey || kp.publicKey.length !== 33) {
      if (!kp.privateKey) throw new Error('WIF without private key');
      kp = ECPair.fromPrivateKey(Buffer.from(kp.privateKey), { network: NITO_NETWORK, compressed: true });
    }
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

async function utxos(addr) {
  try {
    if (walletState.importType === 'hd' && hdManager.hdWallet) {
      const addrType = AddressManager.getAddressType(addr);
      if (addrType === 'p2wpkh') {
        return await utxoScanner.utxosAllForBech32();
      } else if (addrType === 'p2tr') {
        return await utxoScanner.scanHdUtxosForFamilyDescriptor('taproot');
      }
    }
    
    const scan = await rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    if (!scan.success || !scan.unspents) return [];
    
    return scan.unspents.map(u => {
      if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) {
        throw new Error(`Invalid scriptPubKey for UTXO ${u.txid}:${u.vout}`);
      }
      const scriptType = AddressManager.detectScriptType(u.scriptPubKey);
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
    if (walletState.importType === 'hd' && hdManager.hdWallet) {
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

async function signTx(to, amt, isConsolidation = false) {
  return await transactionBuilder.signTx(to, amt, isConsolidation);
}

async function signTxWithPSBT(to, amt, isConsolidation = false) {
  return await transactionBuilder.signTxWithPSBT(to, amt, isConsolidation);
}

async function signTxBatch(to, amt, specificUtxos, isConsolidation = true) {
  return await transactionBuilder.signTxBatch(to, amt, specificUtxos, isConsolidation);
}

async function transferToP2SH(amt) {
  walletState.updateLastActionTime();
  const walletKeyPair = await walletState.getWalletKeyPair();
  const walletPublicKey = await walletState.getWalletPublicKey();
  
  if (!walletState.walletAddress || !walletKeyPair || !walletPublicKey) {
    throw Error(i18next.t('errors.import_first'));
  }
  const { address: p2shAddress } = AddressManager.getP2SHAddress(walletPublicKey);
  return await signTxWithPSBT(p2shAddress, amt);
}

// Legacy global variables for backward compatibility
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
let hdWallet = null;
let currentMnemonic = null;

// Export functions for global access and backward compatibility
window.genAddr = genAddr;
window.importWIF = importWIF;
window.importHex = importHex;
window.utxos = utxos;
window.balance = balance;
window.signTx = signTx;
window.signTxWithPSBT = signTxWithPSBT;
window.signTxBatch = signTxBatch;
window.transferToP2SH = transferToP2SH;
window.rpc = rpc;
window.feeForVsize = (vbytes) => feeManager.calculateFeeForVsize(vbytes);
window.effectiveFeeRate = () => feeManager.getEffectiveFeeRate();

// Expose state getters for messaging compatibility
window.getWalletKeyPair = async () => await walletState.getWalletKeyPair();
window.getWalletPublicKey = async () => await walletState.getWalletPublicKey();
window.getBech32Address = () => walletState.bech32Address;

// Sync legacy variables with walletState
function syncLegacyVariables() {
  walletAddress = walletState.walletAddress;
  legacyAddress = walletState.legacyAddress;
  p2shAddress = walletState.p2shAddress;
  bech32Address = walletState.bech32Address;
  taprootAddress = walletState.taprootAddress;
  importType = walletState.importType;
  lastActionTime = walletState.lastActionTime;
  inactivityTimeout = walletState.inactivityTimeout;
  timerInterval = walletState.timerInterval;
  consolidateButtonInjected = walletState.consolidateButtonInjected;
  hdWallet = hdManager.hdWallet;
  currentMnemonic = hdManager.currentMnemonic;
}

// Update walletState from legacy variables
function updateWalletState() {
  walletState.walletAddress = walletAddress;
  walletState.legacyAddress = legacyAddress;
  walletState.p2shAddress = p2shAddress;
  walletState.bech32Address = bech32Address;
  walletState.taprootAddress = taprootAddress;
  walletState.importType = importType;
  walletState.lastActionTime = lastActionTime;
  walletState.inactivityTimeout = inactivityTimeout;
  walletState.timerInterval = timerInterval;
  walletState.consolidateButtonInjected = consolidateButtonInjected;
}

// Internationalization setup
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

/**
 * UI utility functions
 */
// Helper to show the final consolidation popup (separate name to avoid regex disabling inside loops)
async function showConsolidationFinalPopup(txid) {
  try { await showSuccessPopup(txid); }
  catch (e) { console.error('Failed to show final consolidation popup:', e); }
}

async function showSuccessPopup(txid) {
  // Cleanup existing popup/timers
  try {
    if (_successPopupTimer) { clearTimeout(_successPopupTimer); _successPopupTimer = null; }
    if (_successPopupEl && _successPopupEl.parentNode) { _successPopupEl.parentNode.removeChild(_successPopupEl); }
  } catch (_) {}

  const body = document.body;
  let progress = 0;
  let explorerUrl;
  try {
    explorerUrl = await (typeof getExplorerUrl === "function" ? getExplorerUrl(txid) : Promise.resolve("#"));
  } catch (_) { explorerUrl = "#"; }

  const popup = document.createElement('div');
  popup.className = 'popup';
  popup.style.position = 'fixed';
  popup.style.top = '50%';
  popup.style.left = '50%';
  popup.style.transform = 'translate(-50%, -50%)';
  popup.style.background = body && body.classList && body.classList.contains('dark-mode') ? '#37474f' : 'white';
  popup.style.padding = '20px';
  popup.style.border = '1px solid black';
  popup.style.zIndex = '100000';
  popup.style.pointerEvents = 'auto';
  popup.style.color = body && body.classList && body.classList.contains('dark-mode') ? '#e0e0e0' : '#1e3a8a';

  const _sanitize = (html) => (typeof DOMPurify !== "undefined" && DOMPurify && DOMPurify.sanitize) ? DOMPurify.sanitize(html) : html;
  const _t = (k, fallback) => (typeof i18next !== "undefined" && i18next && i18next.t) ? i18next.t(k) : (fallback || k);

  popup.innerHTML = _sanitize(`
    <p>${_t('popup.success.message','Transaction envoyée avec succès !')}</p>
    <p>${_t('popup.success.progress','Confirmation :')} <span id="progress">0</span>%</p>
    <p>${_t('popup.success.txid','TXID :')} <span id="txidLink">${txid}</span></p>
    <button id="closeSuccessPopup" type="button">${_t('popup.success.close','Fermer')}</button>
  `);
  document.body.appendChild(popup);
  _successPopupEl = popup;

  const progressSpan = popup.querySelector('#progress');
  const txidLinkSpan = popup.querySelector('#txidLink');
  const closeButton = popup.querySelector('#closeSuccessPopup');

  const clearAll = () => {
    try { if (_successPopupTimer) clearTimeout(_successPopupTimer); } catch(_) {}
    _successPopupTimer = null;
    if (_successPopupEl && _successPopupEl.parentNode) {
      _successPopupEl.parentNode.removeChild(_successPopupEl);
    }
    _successPopupEl = null;
  };

  const updateProgress = async () => {
    if (progress >= 100) return;
    progress = Math.min(progress + 1.67, 100);
    if (progressSpan) progressSpan.textContent = Math.round(progress);
    try {
      const confirmed = await (typeof checkTransactionConfirmation === "function" ? checkTransactionConfirmation(txid) : Promise.resolve(true));
      if (confirmed) {
        progress = 100;
        if (progressSpan) progressSpan.textContent = progress;
        if (txidLinkSpan) txidLinkSpan.innerHTML = `<a href="${explorerUrl}" target="_blank" rel="noopener noreferrer">${txid}</a>`;
        return;
      }
    } catch (_) {}
    _successPopupTimer = setTimeout(updateProgress, 10000);
  };

  updateProgress();

  if (closeButton) {
    closeButton.onclick = (e) => { e.preventDefault(); e.stopPropagation(); clearAll(); };
  }
  const onKey = (e) => {
    if (e.key === 'Escape') { clearAll(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);
}


function showLoadingSpinner() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.style.display = 'block';
}

function hideLoadingSpinner() {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) spinner.style.display = 'none';
}

function copyToClipboard(id) {
  walletState.updateLastActionTime();
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
  if (walletState.timerInterval) clearInterval(walletState.timerInterval);
  const timerElement = document.getElementById('inactivityTimer');
  if (!timerElement) return;

  const updateTimer = () => {
    if (!walletState.lastActionTime) {
      timerElement.textContent = '[10:00]';
      return;
    }
    const now = Date.now();
    const elapsed = now - walletState.lastActionTime;
    const remaining = Math.max(0, 600000 - elapsed);
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    if (remaining <= 0) clearInterval(walletState.timerInterval);
  };

  updateTimer();
  walletState.timerInterval = setInterval(updateTimer, 1000);
  timerInterval = walletState.timerInterval;
}

/**
 * Consolidation function
 */
async function consolidateUtxos() {
  
  let finalPopupShown = false;
let lastTxid = null;

  walletState.updateLastActionTime();
  syncLegacyVariables();
  const body = document.body;
  console.log('Consolidate UTXOs button clicked');

  try {
    const walletKeyPair = await walletState.getWalletKeyPair();
    const walletPublicKey = await walletState.getWalletPublicKey();
    
    if (!walletState.walletAddress || !walletKeyPair || !walletPublicKey || !walletState.bech32Address) {
      alert(i18next.t('errors.import_first'));
      console.error('Wallet or addresses not initialized');
      return;
    }

    const sourceType = document.getElementById('debitAddressType').value;
    if (!['bech32', 'p2tr'].includes(sourceType)) {
      alert(i18next.t('errors.consolidation_bech32_only'));
      console.error('Invalid source type:', sourceType);
      return;
    }

    const sourceAddress = (sourceType === 'p2tr') ? walletState.taprootAddress : walletState.bech32Address;
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

    console.log(`Consolidation estimated: ${estimatedSteps} steps for ${initialUtxos.length} UTXOs`);

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

    const originalWalletAddress = walletState.walletAddress;
    const originalWalletPublicKey = await walletState.getWalletPublicKey();
    const originalWalletKeyPair = await walletState.getWalletKeyPair();

    walletState.walletAddress = sourceAddress;
    await walletState.keyManager.storeKey('tempConsolidationKeys', {
      publicKey: (sourceType === 'p2tr') ? (await walletState.getTaprootPublicKey()).toString('hex') : originalWalletPublicKey.toString('hex'),
      privateKey: (sourceType === 'p2tr') ? (await walletState.getTaprootKeyPair()).privateKey.toString('hex') : originalWalletKeyPair.privateKey.toString('hex')
    });

    
    // === Pré-balayage: équilibrer les lots de 500 pour garantir >= 1 UTXO qui couvre les frais ===
    (function prebalanceUtxos() {
      try {
        const destScriptType = AddressManager.getAddressType(sourceAddress);
        const feeForFullBatch = feeManager.calculateFeeForVsize(
          feeManager.estimateVBytes(sourceType, utxosPerBatch, [destScriptType])
        ); // en sats, pour 500 entrées et 1 sortie
        const feeForFullBatchNito = feeForFullBatch / 1e8;

        // Séparer en "grands" et "petits" UTXOs selon la capacité à couvrir à eux seuls les frais
        const big = [];
        const small = [];
        for (const u of initialUtxos) {
          const sats = Math.round(u.amount * 1e8);
          if (sats >= feeForFullBatch) big.push(u); else small.push(u);
        }

        // Construire un ordre équilibré: chaque lot de 500 commence avec 1 "big" si possible
        const numBatches = Math.ceil(initialUtxos.length / utxosPerBatch);
        const balanced = [];
        let b = 0;
        while (b < numBatches) {
          const batch = [];
          // 1) Réserver un "big" pour ce lot si disponible
          if (big.length > 0) batch.push(big.shift());
          // 2) Compléter avec des "small"
          while (batch.length < utxosPerBatch && small.length > 0) {
            batch.push(small.shift());
          }
          // 3) Si toujours pas 500 (manque de small), compléter avec big restants
          while (batch.length < utxosPerBatch && big.length > 0) {
            batch.push(big.shift());
          }
          balanced.push(...batch);
          b++;
        }
        // Ajouter les éventuels restes (si numBatches*500 > total ou inversement)
        if (small.length || big.length) balanced.push(...small, ...big);

        // Affecter la liste équilibrée
        var balancedUtxos = balanced;
        // Note: si jamais il n'y a pas assez de "big" pour chaque lot, certains lots n'auront pas
        // un UTXO unique couvrant les frais. Ils auront néanmoins la plus grande dispersion possible.
      } catch (e) {
        console.warn('⚠️ Pré-balayage UTXOs non appliqué (continuation sans équilibrage):', e?.message || e);
        var balancedUtxos = [...initialUtxos];
      }
      // Exposer balancedUtxos dans la portée
      window.__balancedUtxos = balancedUtxos;
    })();
    let currentUtxos = window.__balancedUtxos || [...initialUtxos];
    let stepCount = 1;
    let totalSuccess = 0;
    let lastTxid = null;
    let consecutiveIdenticalScans = 0;
    const MAX_IDENTICAL_SCANS = 3;

    try {
      while (currentUtxos.length > 1 && stepCount <= maxSteps) {
        console.log(`${stepCount}/${maxSteps} (${Math.round((stepCount/maxSteps)*100)}%) - UTXOs remaining: ${currentUtxos.length}`);

        if (currentUtxos.length === 1) {
          console.log("Target reached: 1 UTXO remaining");
          break;
        }

        if (currentUtxos.length === 2 && consecutiveIdenticalScans >= MAX_IDENTICAL_SCANS) {
          console.log(`Consolidation successful: 2 UTXOs remaining after ${consecutiveIdenticalScans} identical scans`);
          break;
        }

        const batchUtxos = currentUtxos.slice(0, 500);
        currentUtxos = currentUtxos.slice(500);

        let batchTotal = 0;
        for (const u of batchUtxos) {
          batchTotal += Math.round(u.amount * 1e8);
        }

        const target = batchTotal;

        if (target < feeManager.getDustThreshold(sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh')) {
          console.log(`Amount too small (${target / 1e8} NITO), consolidation finished`);
          break;
        }

        const inputSize = (sourceType === 'p2tr') ? 57.5 : 68;
        const destScriptType = AddressManager.getAddressType(sourceAddress);
        const dustSats = feeManager.getDustThreshold(destScriptType);
        let estimatedFees = feeManager.calculateFeeForVsize(
          feeManager.estimateVBytes(sourceType, batchUtxos.length, [destScriptType])
        );
        let amountToSend = (batchTotal - estimatedFees) / 1e8;

        // 🔧 Étendre dynamiquement le lot si la sortie est <= dust
        while ((amountToSend * 1e8) <= dustSats && currentUtxos.length > 0) {
          const take = Math.min(utxosPerBatch, currentUtxos.length);
          const extras = currentUtxos.splice(0, take);
          for (const u of extras) batchTotal += Math.round(u.amount * 1e8);
          batchUtxos.push(...extras);

          estimatedFees = feeManager.calculateFeeForVsize(
            feeManager.estimateVBytes(sourceType, batchUtxos.length, [destScriptType])
          );
          amountToSend = (batchTotal - estimatedFees) / 1e8;
          console.log(
            `⬆️ Lot étendu: ${batchUtxos.length} entrées, frais estimés ${(estimatedFees/1e8).toFixed(8)} NITO, sortie ${(amountToSend).toFixed(8)} NITO`
          );
        }

        // Si même agrandi, on ne dépasse pas le dust, abandon proprement
        if ((amountToSend * 1e8) <= dustSats) {
          console.log(
            `⛔ Étape ${stepCount} ignorée: total après frais ${((batchTotal - estimatedFees)/1e8).toFixed(8)} NITO ≤ dust ${(dustSats/1e8).toFixed(8)} NITO`
          );
          break;
        }

        console.log(`Step ${stepCount} - Consolidation: ${batchUtxos.length} UTXOs → 1 UTXO (${amountToSend} NITO)`);
        try {
          const result = await transactionBuilder.signTxBatch(sourceAddress, amountToSend, batchUtxos, true);
          const hex = result.hex;
          const txid = await rpc('sendrawtransaction', [hex]);
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;

          console.log(`Step ${stepCount} successful, TXID: ${txid}`);
// await showSuccessPopup(txid); // disabled inside consolidation
          totalSuccess++;
          lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;

          console.log('Waiting for confirmation (5 seconds)...');
          await sleepJitter(5000, 300, true);

          console.log(`UTXOs remaining to process: ${currentUtxos.length}`);

          if (currentUtxos.length <= 1) {
            console.log('CONSOLIDATION COMPLETE!');
            try { await showConsolidationFinalPopup(txid); finalPopupShown = true; } catch(e) { console.error(e); }
            break;
          }

          consecutiveIdenticalScans = 0;

        } catch (error) {
          if (error.message.includes('txn-mempool-conflict')) {
            console.log(`Mempool conflict step ${stepCount}, waiting 10s...`);
            await sleepJitter(10000, 300, true);
            currentUtxos = await utxos(sourceAddress);
            continue;
          } else if (error.message.includes('Transaction already in block chain')) {
            console.log(`Transaction already confirmed at step ${stepCount}`);
            totalSuccess++;
            await sleepJitter(5000, 300, true);
            currentUtxos = await utxos(sourceAddress);
          } else {
            throw error;
          }
        }
      }
      if (currentUtxos.length <= 1) {
        alert(i18next.t('consolidation_single_utxo_completed'));
        setTimeout(() => document.getElementById('refreshBalanceButton').click(), 3000);
      } else {
        alert(i18next.t('consolidation_stopped', { utxos: currentUtxos.length }));
      }

    } catch (e) {
      hideLoadingSpinner();
      alert(i18next.t('errors.consolidation_error', { message: e.message }));
      console.error('Consolidation error:', e);
    } finally {
      hideLoadingSpinner();
      walletState.walletAddress = originalWalletAddress;
      syncLegacyVariables();
    }

  } catch (e) {
    hideLoadingSpinner();
    alert(i18next.t('errors.consolidation_error', { message: e.message }));
    console.error('Consolidation error:', e);
  }
  if (!finalPopupShown && lastTxid) {
    window._lastConsolidationTxid = lastTxid;
    window.lastTxid = lastTxid;
    try { await showConsolidationFinalPopup(lastTxid); } catch (e) { console.error('Failed to show final success popup:', e); }
  }
}
// Helper function for DOM element selection
const $ = id => document.getElementById(id);

// Export global functions
window.copyToClipboard = copyToClipboard;
window.consolidateUtxos = consolidateUtxos;
window.showSuccessPopup = showSuccessPopup;

/**
 * Main initialization and event handlers
 */
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

    await feeManager.initNetworkParams();
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
      walletState.updateLastActionTime();
      syncLegacyVariables();
      try {
        const mnemonic = hdManager.generateMnemonic(24);
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const hdWallet = bip32.fromSeed(seed);
        const hdMasterKey = hdWallet.toBase58();

        const bech32Node = hdWallet.derivePath("m/84'/0'/0'/0/0");
        const legacyNode = hdWallet.derivePath("m/44'/0'/0'/0/0");
        const p2shNode = hdWallet.derivePath("m/49'/0'/0'/0/0");
        const pubkey = Buffer.from(bech32Node.publicKey);
        const keyPair = ECPair.fromPrivateKey(bech32Node.privateKey, { network: NITO_NETWORK });

        const p2pkh = bitcoin.payments.p2pkh({ pubkey: Buffer.from(legacyNode.publicKey), network: NITO_NETWORK });
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkey, network: NITO_NETWORK });
        const p2sh = bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey: Buffer.from(p2shNode.publicKey), network: NITO_NETWORK }), network: NITO_NETWORK });

        const taprootNode = hdWallet.derivePath("m/86'/0'/0'/0/0");
        const tapInternalPubkey = TaprootUtils.toXOnly(taprootNode.publicKey);
        const p2tr = bitcoin.payments.p2tr({ internalPubkey: tapInternalPubkey, network: NITO_NETWORK });

        const taprootKeyPair = ECPair.fromPrivateKey(taprootNode.privateKey, { network: NITO_NETWORK });

        const addresses = {
          legacy: p2pkh.address,
          p2sh: p2sh.address,
          bech32: p2wpkh.address,
          taproot: p2tr.address
        };

        if (!await AddressManager.validateAddress(addresses.legacy) ||
            !await AddressManager.validateAddress(addresses.p2sh) ||
            !await AddressManager.validateAddress(addresses.bech32) ||
            !await AddressManager.validateAddress(addresses.taproot)) {
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
      walletState.updateLastActionTime();
      syncLegacyVariables();
      try {
        const input = $('privateKeyWIF').value.trim();
        const hdPassphrase = '';

        if (!input) {
          alert(i18next.t('errors.import_empty'));
          return;
        }

        let addresses;
        walletState.importType = '';

        if (input.startsWith('xprv')) {
          addresses = await hdManager.importHDWallet(input, hdPassphrase);
          walletState.importType = 'hd';
        } else if (input.split(' ').length >= 12 && input.split(' ').length <= 24) {
          addresses = await hdManager.importHDWallet(input, hdPassphrase);
          walletState.importType = 'hd';
        } else if (/^[0-9a-fA-F]{64}$/.test(input)) {
          addresses = importHex(input);
          walletState.importType = 'single';
          await walletState.keyManager.storeKey('bech32KeyPair', {
            privateKey: addresses.keyPair.privateKey.toString('hex'),
            publicKey: addresses.publicKey.toString('hex')
          });
        } else {
          addresses = importWIF(input);
          walletState.importType = 'single';
          await walletState.keyManager.storeKey('bech32KeyPair', {
            privateKey: addresses.keyPair.privateKey.toString('hex'),
            publicKey: addresses.publicKey.toString('hex')
          });
        }

        if (!await AddressManager.validateAddress(addresses.legacy) ||
            !await AddressManager.validateAddress(addresses.p2sh) ||
            !await AddressManager.validateAddress(addresses.bech32) ||
            (walletState.importType === 'hd' && addresses.taproot && !await AddressManager.validateAddress(addresses.taproot))) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        walletState.legacyAddress = addresses.legacy;
        walletState.p2shAddress = addresses.p2sh;
        walletState.bech32Address = addresses.bech32;
        walletState.taprootAddress = addresses.taproot || '';
        walletState.walletAddress = addresses.bech32;

        const bech32Balance = await balance(walletState.bech32Address);
        let taprootBalance = 0;
        let addressDisplay = `
          Bech32: <span id="bech32Address">${walletState.bech32Address}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (${bech32Balance.toFixed(8)} )
        `;

        if (walletState.importType === 'hd') {
          taprootBalance = await balance(walletState.taprootAddress);
          addressDisplay += `<br>Bech32m (Taproot): <span id="taprootAddress">${walletState.taprootAddress}</span> <button class="copy-btn" id="copyTaprootAddr">📋</button> (${taprootBalance.toFixed(8)} )`;
        }

        $('walletAddress').innerHTML = DOMPurify.sanitize(addressDisplay);
        $('walletBalance').innerHTML = `Bech32: ${bech32Balance.toFixed(8)}` + (walletState.importType === 'hd' ? ` | Bech32m (Taproot): ${taprootBalance.toFixed(8)} ` : ' NITO');

        const filteredAddresses = {
          legacy: addresses.legacy,
          p2sh: addresses.p2sh,
          bech32: addresses.bech32,
          taproot: addresses.taproot
        };
        console.log('Wallet imported (public info only):', filteredAddresses);

        // Sync for messaging compatibility
        window.hasWallet = () => walletState.keyManager.hasKey('bech32KeyPair');
        window.getWalletAddress = () => walletState.bech32Address;
        window.getTaprootAddress = () => walletState.taprootAddress;
        window.isWalletReady = () => walletState.bech32Address && walletState.keyManager.hasKey('bech32KeyPair');

        // Variables d'adresses uniquement (pas de clés)
        window.bech32Address = walletState.bech32Address;
        window.taprootAddress = walletState.taprootAddress;
        window.rpc = rpc;
        window.balance = balance;

        // Variables nullifiées pour sécurité
        window.walletKeyPair = null;
        window.walletPublicKey = null;

        console.log("Interface sécurisée exposée pour:", walletState.bech32Address);

        syncLegacyVariables();

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
        if (copyTaprootAddr && walletState.importType === 'hd') copyTaprootAddr.onclick = () => copyToClipboard('taprootAddress');

        const debitTypeSelect = $('debitAddressType');
        if (debitTypeSelect) {
          debitTypeSelect.innerHTML = '';

          if (walletState.importType === 'single') {
            const bech32Option = document.createElement('option');
            bech32Option.value = 'bech32';
            bech32Option.textContent = 'bech32';
            debitTypeSelect.appendChild(bech32Option);
          } else if (walletState.importType === 'hd') {
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
        if (!walletState.consolidateButtonInjected) {
          const consolidateButton = document.createElement('button');
          consolidateButton.id = 'consolidateButton';
          consolidateButton.className = 'consolidate-button';
          consolidateButton.textContent = i18next.t('send_section.consolidate_button');
          consolidateContainer.appendChild(consolidateButton);
          consolidateButton.onclick = () => consolidateUtxos();
          walletState.consolidateButtonInjected = true;
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
              const sourceAddress = sourceType === 'p2tr' ? walletState.taprootAddress : walletState.bech32Address;
              const ins = await utxos(sourceAddress);
              const workingIns = await filterOpReturnUtxos(ins);
              if (!workingIns.length) {
                hideLoadingSpinner();
                return alert(i18next.t('errors.no_utxo_available_max'));
              }

              workingIns.sort((a, b) => b.amount - a.amount);
              const selectedIns = workingIns;

              let total = selectedIns.reduce((sum, u) => sum + Math.round(u.amount * 1e8), 0);

              const destScriptType = AddressManager.getAddressType(dest);
              const fees = feeManager.calculateFeeForVsize(feeManager.estimateVBytesMixed(selectedIns, [destScriptType]));

              const maxAmount = (total - fees) / 1e8;
              const maxSats = Math.round((total - fees));
              const dust = feeManager.getDustThreshold(destScriptType);
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
        
        syncLegacyVariables();
      } catch (e) {
        alert(i18next.t('errors.import_error', { message: e.message }));
        console.error('Import error:', e);
      }
    };

    $('refreshBalanceButton').onclick = async () => {
      walletState.updateLastActionTime();
      syncLegacyVariables();
      if (!walletState.walletAddress) return alert(i18next.t('errors.import_first'));
      try {
        const bech32Balance = await balance(walletState.bech32Address);
        let taprootBalance = 0;
        let balanceDisplay = `Bech32: ${bech32Balance.toFixed(8)} `;

        if (walletState.importType === 'hd') {
          taprootBalance = await balance(walletState.taprootAddress);
          balanceDisplay = `Bech32: ${bech32Balance.toFixed(8)} | Bech32m (Taproot): ${taprootBalance.toFixed(8)} `;
        }

        if (!await AddressManager.validateAddress(walletState.bech32Address) || (walletState.importType === 'hd' && !await AddressManager.validateAddress(walletState.taprootAddress))) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        let addressDisplay = `
          Bech32: <span id="bech32Address">${walletState.bech32Address}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (${bech32Balance.toFixed(8)} )
        `;

        if (walletState.importType === 'hd') {
          addressDisplay += `<br>Bech32m (Taproot): <span id="taprootAddress">${walletState.taprootAddress}</span> <button class="copy-btn" id="copyTaprootAddr">📋</button> (${taprootBalance.toFixed(8)} )`;
        }

        $('walletAddress').innerHTML = DOMPurify.sanitize(addressDisplay);
        $('walletBalance').innerHTML = balanceDisplay;

        const copyBech32Addr = $('copyBech32Addr');
        if (copyBech32Addr) copyBech32Addr.onclick = () => copyToClipboard('bech32Address');

        const copyTaprootAddr = $('copyTaprootAddr');
        if (copyTaprootAddr && walletState.importType === 'hd') copyTaprootAddr.onclick = () => copyToClipboard('taprootAddress');
        
        syncLegacyVariables();
      } catch (e) {
        alert(i18next.t('errors.refresh_error', { message: e.message }));
        console.error('Refresh error:', e);
      }
    };

    $('prepareTxButton').onclick = async () => {
      walletState.updateLastActionTime();
      syncLegacyVariables();
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
        const destType = AddressManager.getAddressType(dest);
        let hex;

        try {
          let signerAddress;
          let signerPublicKey;
          let signerKeyPair;

          if (sourceType === 'p2tr') {
            signerAddress = walletState.taprootAddress;
            signerPublicKey = await walletState.getTaprootPublicKey();
            signerKeyPair = await walletState.getTaprootKeyPair();
          } else if (sourceType === 'bech32') {
            signerAddress = walletState.bech32Address;
            signerPublicKey = await walletState.getWalletPublicKey();
            signerKeyPair = await walletState.getWalletKeyPair();
          } else {
            signerAddress = sourceType === 'legacy' ? walletState.legacyAddress : sourceType === 'p2sh' ? walletState.p2shAddress : walletState.bech32Address;
            signerPublicKey = await walletState.getWalletPublicKey();
            signerKeyPair = await walletState.getWalletKeyPair();
          }

          const originalWalletAddress = walletState.walletAddress;

          walletState.walletAddress = signerAddress;
          await walletState.keyManager.storeKey('tempSigningKeys', {
            publicKey: signerPublicKey.toString('hex'),
            privateKey: signerKeyPair.privateKey.toString('hex')
          });

          let result;
          try {
            if (sourceType === 'bech32') {
              result = await signTx(dest, amt);
            } else {
              result = await signTxWithPSBT(dest, amt);
            }
          } finally {
            walletState.walletAddress = originalWalletAddress;
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
      walletState.updateLastActionTime();
      syncLegacyVariables();
      const hex = $('signedTx').textContent.trim();
      if (!hex) return alert(i18next.t('errors.no_transaction'));

      try {
        showLoadingSpinner();
        const txid = await rpc('sendrawtransaction', [hex]);
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;
  lastTxid = txid;
  window._lastConsolidationTxid = lastTxid;
  window.lastTxid = lastTxid;
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
      walletState.updateLastActionTime();
      syncLegacyVariables();
      ['destinationAddress', 'amountNito'].forEach(id => $(id).value = '');
      ['signedTx'].forEach(id => $(id).textContent = '');
      $('txHexContainer').style.display = 'none';
    };
    
  } catch (e) {
    alert(i18next.t('errors.node_connection', { message: e.message }));
    console.error('Connection error:', e);
  }
});
