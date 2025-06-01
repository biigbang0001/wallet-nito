import * as bitcoin from 'https://esm.sh/bitcoinjs-lib@6.1.5?bundle';
import * as tinysecp from 'https://esm.sh/@bitcoin-js/tiny-secp256k1-asmjs@2.2.3';
import ECPairFactory from 'https://esm.sh/ecpair@3.0.0';
import { Buffer } from 'https://esm.sh/buffer@6.0.3';
window.Buffer = Buffer;

const ECPair = ECPairFactory(tinysecp);

const NITO_NETWORK = {
  messagePrefix: '\x18Nito Signed Message:\n',
  bech32: 'nito',
  bip32: { public: 0x0488B21E, private: 0x0488ADE4 },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80
};

const NODE_URL = '/api/';
let MIN_FEE_RATE = 0.00001;
let DYNAMIC_FEE_RATE = null;
const DUST_RELAY_AMOUNT = 3000;
const DUST_AMOUNT = {
  p2pkh: 546,
  p2wpkh: 294,
  p2sh: 540
};
const MIN_CONSOLIDATION_FEE = 0.0001;

let walletAddress = '';
let legacyAddress = '';
let p2shAddress = '';
let bech32Address = '';
let walletPublicKey = null;
let walletKeyPair = null;
let consolidateButtonInjected = false;
let lastActionTime = null;
let inactivityTimeout = null;
let timerInterval = null;

// Initialiser i18next avec l'objet global window.i18next
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
  // Traduire les éléments avec l'attribut data-i18n
  document.querySelectorAll('[data-i18n]').forEach(element => {
    const key = element.getAttribute('data-i18n');
    if (key.startsWith('[placeholder]')) {
      const actualKey = key.replace('[placeholder]', '');
      element.setAttribute('placeholder', i18next.t(actualKey));
    } else {
      element.textContent = i18next.t(key);
    }
  });

  // Traduire spécifiquement le titre <h1> (contient une image)
  const h1 = document.querySelector('h1');
  if (h1 && h1.childNodes[1]) {
    h1.childNodes[1].textContent = i18next.t('title');
  }

  // Traduire le contenu de l'élément warning avec HTML
  const warning = document.querySelector('.warning');
  if (warning) {
    warning.innerHTML = DOMPurify.sanitize(i18next.t('generate_section.warning'));
  }

  // Traduire le bouton de consolidation s'il existe
  const consolidateButton = document.getElementById('consolidateButton');
  if (consolidateButton) {
    consolidateButton.textContent = i18next.t('send_section.consolidate_button');
  }
}

async function rpc(method, params) {
  try {
    const res = await fetch(NODE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
    });
    const text = await res.text();
    console.log('RPC raw response:', text);
    if (!res.ok) throw new Error(`HTTP Error: ${res.status} - ${text}`);
    const data = JSON.parse(text);
    if (data.error) throw new Error(data.error.message);
    return data.result;
  } catch (e) {
    console.error('RPC Error:', method, e);
    throw e;
  }
}

// Fonction pour récupérer la valeur du compteur
async function fetchCounter() {
  try {
    const res = await fetch('/api/get-counter', { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();
    return data.count;
  } catch (e) {
    console.error('Error fetching counter:', e);
    return 0; // Valeur par défaut en cas d'erreur
  }
}

// Fonction pour incrémenter le compteur
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

// Mettre à jour l'affichage du compteur
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
      const confirmed = await checkTransactionConfirmation(txid);
      if (confirmed) {
        progress = 100;
        progressSpan.textContent = progress;
        txidLinkSpan.innerHTML = `<a href="${explorerUrl}" target="_blank">${txid}</a>`;
      } else {
        setTimeout(updateProgress, 10000);
      }
    }
  };

  updateProgress();

  closeButton.onclick = () => document.body.removeChild(popup);
}

async function initNetworkParams() {
  try {
    const feeInfo = await rpc('estimatesmartfee', [6]);
    DYNAMIC_FEE_RATE = feeInfo.feerate || MIN_FEE_RATE;
    console.log('Dynamic fee rate:', DYNAMIC_FEE_RATE);
  } catch (e) {
    DYNAMIC_FEE_RATE = MIN_FEE_RATE;
    console.error('Error fetching fees:', e);
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

function importWIF(wif) {
  try {
    const kp = ECPair.fromWIF(wif, NITO_NETWORK);
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
    const scan = await rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    if (!scan.success || !scan.unspents) return [];
    return scan.unspents.map(u => {
      if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) {
        throw new Error(`Invalid scriptPubKey for UTXO ${u.txid}:${u.vout}`);
      }
      const scriptBuffer = Buffer.from(u.scriptPubKey, 'hex');
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
    const scan = await rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    return scan.total_amount || 0;
  } catch (e) {
    console.error('Error fetching balance:', e);
    throw e;
  }
}

function getAddressType(addr) {
  try {
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

function estimateTxSize(scriptType, numInputs, numOutputs, destScriptType) {
  const inputSizes = { p2pkh: 148, p2wpkh: 68, p2sh: 91 };
  const outputSizes = { p2pkh: 34, p2wpkh: 31, p2sh: 32 };
  const overhead = 10;
  const inputSize = inputSizes[scriptType] || inputSizes.p2wpkh;
  const outputSize = outputSizes[destScriptType] || outputSizes.p2wpkh;
  return overhead + inputSize * numInputs + outputSize * numOutputs;
}

function getP2SHAddress(pubkeyBuffer) {
  try {
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
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

async function signTx(to, amt) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));

  console.log('Starting Bech32 to Bech32 transaction preparation for:', to, 'Amount:', amt);

  const ins = await utxos(walletAddress);
  if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

  const sendScriptType = getAddressType(walletAddress);
  if (sendScriptType !== 'p2wpkh') throw new Error(i18next.t('errors.only_bech32_supported'));

  const destScriptType = getAddressType(to);
  console.log('Script type - sender:', sendScriptType, 'destination:', destScriptType);

  const target = Math.round(amt * 1e8);
  ins.sort((a, b) => b.amount - a.amount);
  let total = 0;
  const selectedIns = [];
  for (const u of ins) {
    selectedIns.push(u);
    total += Math.round(u.amount * 1e8);
    if (total >= target) break;
  }

  const txSize = estimateTxSize(sendScriptType, selectedIns.length, 1, destScriptType);
  const feeRate = DYNAMIC_FEE_RATE || MIN_FEE_RATE;
  const inputFee = Math.max(Math.round(txSize * (feeRate * 1e8) / 1000), Math.round(MIN_CONSOLIDATION_FEE * 1e8));

  console.log('Estimated size:', txSize, 'vbytes, Fee:', inputFee / 1e8, 'NITO');

  const fees = inputFee;
  const change = total - target - fees;
  if (change < 0) throw new Error(i18next.t('errors.insufficient_funds'));

  const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
  psbt.setVersion(2);

  for (const utxo of selectedIns) {
    const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) }
    });
  }

  if (target < getDustThreshold(destScriptType)) {
    throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: getDustThreshold(destScriptType) }));
  }
  psbt.addOutput({ address: to, value: target });

  if (change > getDustThreshold('p2wpkh')) {
    psbt.addOutput({ address: walletAddress, value: change });
  }

  const signer = {
    network: walletKeyPair.network,
    privateKey: walletKeyPair.privateKey,
    publicKey: walletPublicKey,
    sign: (hash) => Buffer.from(walletKeyPair.sign(hash))
  };

  for (let i = 0; i < selectedIns.length; i++) {
    psbt.signInput(i, signer, [bitcoin.Transaction.SIGHASH_ALL]);
  }

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  const hex = tx.toHex();

  console.log('Transaction hex:', hex, 'TXID:', tx.getId());
  return hex;
}

async function signTxWithPSBT(to, amt) {
  updateLastActionTime();
  if (!walletAddress || !walletKeyPair || !walletPublicKey) throw Error(i18next.t('errors.import_first'));

  console.log('Starting transaction preparation for:', to, 'Amount:', amt);

  const ins = await utxos(walletAddress);
  if (!ins.length) throw new Error(i18next.t('errors.no_utxo'));

  const sendScriptType = getAddressType(walletAddress);
  const destScriptType = getAddressType(to);
  console.log('Script type - sender:', sendScriptType, 'destination:', destScriptType);

  const target = Math.round(amt * 1e8);
  ins.sort((a, b) => b.amount - a.amount);
  let total = 0;
  const selectedIns = [];
  for (const u of ins) {
    selectedIns.push(u);
    total += Math.round(u.amount * 1e8);
    if (total >= target) break;
  }

  const txSize = estimateTxSize(sendScriptType, selectedIns.length, 1, destScriptType);
  const feeRate = DYNAMIC_FEE_RATE || MIN_FEE_RATE;
  const inputFee = Math.max(Math.round(txSize * (feeRate * 1e8) / 1000), Math.round(MIN_CONSOLIDATION_FEE * 1e8));

  console.log('Estimated size:', txSize, 'vbytes, Fee:', inputFee / 1e8, 'NITO');

  const fees = inputFee;
  const change = total - target - fees;
  if (change < 0) throw new Error(i18next.t('errors.insufficient_funds'));

  const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
  psbt.setVersion(2);

  for (const utxo of selectedIns) {
    const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
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
    } else {
      throw new Error(i18next.t('errors.unsupported_address_type'));
    }
  }

  if (target < getDustThreshold(destScriptType)) {
    throw new Error(i18next.t('errors.low_amount', { amount: target, minimum: getDustThreshold(destScriptType) }));
  }
  psbt.addOutput({ address: to, value: target });

  if (change > getDustThreshold('p2wpkh')) {
    psbt.addOutput({ address: walletAddress, value: change });
  }

  const signer = {
    network: walletKeyPair.network,
    privateKey: walletKeyPair.privateKey,
    publicKey: walletPublicKey,
    sign: (hash) => Buffer.from(walletKeyPair.sign(hash))
  };

  for (let i = 0; i < selectedIns.length; i++) {
    try {
      psbt.signInput(i, signer, [bitcoin.Transaction.SIGHASH_ALL]);
    } catch (e) {
      console.error(`Signature error for input ${i}:`, e);
      throw new Error(i18next.t('errors.signature_failed', { input: i, message: e.message }));
    }
  }

  try {
    psbt.finalizeAllInputs();
  } catch (e) {
    console.error('Error finalizing inputs:', e);
    throw new Error(i18next.t('errors.finalization_failed', { message: e.message }));
  }

  const tx = psbt.extractTransaction();
  const hex = tx.toHex();

  console.log('Transaction PSBT hex:', hex, 'TXID:', tx.getId());
  return hex;
}

async function consolidateUtxos() {
  updateLastActionTime();
  const body = document.body;
  console.log('Consolidate UTXOs button clicked');
  try {
    if (!walletAddress || !walletKeyPair || !walletPublicKey || !legacyAddress || !p2shAddress || !bech32Address) {
      alert(i18next.t('errors.import_first'));
      console.error('Wallet or addresses not initialized');
      return;
    }

    const sourceType = $('debitAddressType').value;
    if (!['p2sh', 'bech32'].includes(sourceType)) {
      alert(i18next.t('errors.consolidation_invalid_type'));
      console.error('Invalid source type:', sourceType);
      return;
    }

    const to = sourceType === 'p2sh' ? p2shAddress : bech32Address;
    const sourceAddress = to;
    console.log('Consolidating to:', to);

    const confirm = await new Promise(resolve => {
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
        <p>${i18next.t('popup.consolidation.confirm_message', { address: to })}</p>
        <button id="confirmConsolidate">${i18next.t('popup.consolidation.confirm_button')}</button>
        <button id="cancelConsolidate">${i18next.t('popup.consolidation.cancel_button')}</button>
      `);
      document.body.appendChild(popup);

      const confirmButton = document.getElementById('confirmConsolidate');
      const cancelButton = document.getElementById('cancelConsolidate');

      if (!confirmButton || !cancelButton) {
        console.error('Popup buttons not found');
        document.body.removeChild(popup);
        resolve(false);
        return;
      }

      confirmButton.onclick = () => {
        document.body.removeChild(popup);
        resolve(true);
      };
      cancelButton.onclick = () => {
        document.body.removeChild(popup);
        resolve(false);
      };
    });

    if (!confirm) {
      console.log('Consolidation cancelled by user');
      return;
    }

    console.log('Fetching UTXOs for:', sourceAddress);
    await new Promise(resolve => setTimeout(resolve, 1000));
    const ins = await utxos(sourceAddress);
    if (ins.length < 2) {
      alert(i18next.t('errors.consolidation_low_utxo'));
      console.log('Less than 2 UTXOs found:', ins.length);
      return;
    }

    console.log('Number of UTXOs to consolidate:', ins.length);

    const sendScriptType = getAddressType(sourceAddress);
    const destScriptType = getAddressType(to);

    let total = 0;
    for (const u of ins) {
      total += Math.round(u.amount * 1e8);
    }
    console.log('Total UTXO amount:', total / 1e8, 'NITO');

    const txSize = estimateTxSize(sendScriptType, ins.length, 1, destScriptType);
    const feeRate = DYNAMIC_FEE_RATE || MIN_FEE_RATE;
    const inputFee = Math.max(Math.round(txSize * (feeRate * 1e8) / 1000), Math.round(MIN_CONSOLIDATION_FEE * 1e8));

    console.log('Estimated size:', txSize, 'vbytes, Fee:', inputFee / 1e8, 'NITO');

    const target = total - inputFee;
    if (target < getDustThreshold(destScriptType)) {
      alert(i18next.t('errors.consolidation_low_amount'));
      console.error('Target amount too low:', target / 1e8, 'NITO');
      return;
    }

    walletAddress = sourceAddress;

    console.log('Preparing consolidation transaction');
    await new Promise(resolve => setTimeout(resolve, 500));

    let hex;
    if (sourceType === 'bech32' && destScriptType === 'p2wpkh') {
      hex = await signTx(to, target / 1e8);
    } else {
      hex = await signTxWithPSBT(to, target / 1e8);
    }

    console.log('Consolidation hex:', hex, 'TXID:', bitcoin.Transaction.fromHex(hex).getId());

    console.log('Broadcasting transaction');
    await new Promise(resolve => setTimeout(resolve, 1000));
    const txid = await rpc('sendrawtransaction', [hex]);

    await showSuccessPopup(txid);
    console.log('Consolidation successful, TXID:', txid);
    setTimeout(() => $('refreshBalanceButton').click(), 3000);
  } catch (e) {
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
    const remaining = Math.max(0, 600000 - elapsed); // 600000ms = 10min
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
  inactivityTimeout = setTimeout(clearSensitiveData, 600000); // 10min
  updateInactivityTimer();
}

function clearSensitiveData() {
  walletKeyPair = null;
  walletPublicKey = null;
  legacyAddress = '';
  p2shAddress = '';
  bech32Address = '';
  walletAddress = '';
  const privateKeyHex = document.getElementById('privateKeyHex');
  const privateKey = document.getElementById('privateKey');
  const generatedAddress = document.getElementById('generatedAddress');
  if (privateKeyHex) privateKeyHex.textContent = '';
  if (privateKey) privateKey.textContent = '';
  if (generatedAddress) generatedAddress.innerHTML = '';
  console.log('Sensitive data cleared');
}

window.copyToClipboard = copyToClipboard;

const $ = id => document.getElementById(id);

window.addEventListener('load', async () => {
  console.log('Loading wallet.js');
  try {
    const requiredIds = [
      'themeToggle', 'languageSelect', 'generateButton', 'importWalletButton', 'refreshBalanceButton',
      'prepareTxButton', 'broadcastTxButton', 'cancelTxButton',
      'destinationAddress', 'amountNito', 'feeNito', 'debitAddressType', 'privateKeyWIF',
      'walletAddress', 'walletBalance', 'txHexContainer', 'signedTx', 'copyGenHex',
      'copyGenWif', 'copyTxHex', 'generatedAddress',
      'privateKeyHex', 'privateKey', 'revealHex', 'revealWif', 'revealWifInput',
      'inactivityTimer',
      'keyCounter' // Ajout pour le compteur
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

    // Récupérer et afficher la valeur initiale du compteur au chargement
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

    $('copyGenHex').onclick = () => copyToClipboard('privateKeyHex');
    $('copyGenWif').onclick = () => copyToClipboard('privateKey');
    $('copyTxHex').onclick = () => copyToClipboard('signedTx');

    $('generateButton').onclick = async () => {
      updateLastActionTime();
      try {
        const kp = ECPair.makeRandom({ network: NITO_NETWORK });
        const privateKeyHex = Buffer.from(kp.privateKey).toString('hex');
        const privateKey = kp.toWIF();
        const pubkeyBuffer = Buffer.from(kp.publicKey);
        const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
        const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });

        const addresses = {
          legacy: p2pkh.address,
          p2sh: p2sh.address,
          bech32: p2wpkh.address
        };

        if (!await validateAddress(addresses.legacy) ||
            !await validateAddress(addresses.p2sh) ||
            !await validateAddress(addresses.bech32)) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        const legacyBalance = await balance(addresses.legacy);
        const p2shBalance = await balance(addresses.p2sh);
        const bech32Balance = await balance(addresses.bech32);

        $('privateKeyHex').textContent = privateKeyHex;
        $('privateKey').textContent = privateKey;
        $('privateKeyHex').classList.add('blurred');
        $('privateKey').classList.add('blurred');

        $('generatedAddress').innerHTML = DOMPurify.sanitize(`
          Legacy: <span id="generatedLegacyAddress">${addresses.legacy}</span> <button class="copy-btn" id="copyGeneratedLegacyAddr">📋</button> (Solde: ${legacyBalance.toFixed(8)} NITO)<br>
          P2SH: <span id="generatedP2shAddress">${addresses.p2sh}</span> <button class="copy-btn" id="copyGeneratedP2shAddr">📋</button> (Solde: ${p2shBalance.toFixed(8)} NITO)<br>
          Bech32: <span id="generatedBech32Address">${addresses.bech32}</span> <button class="copy-btn" id="copyGeneratedBech32Addr">📋</button> (Solde: ${bech32Balance.toFixed(8)} NITO)
        `);

        const copyGeneratedLegacyAddr = $('copyGeneratedLegacyAddr');
        const copyGeneratedP2shAddr = $('copyGeneratedP2shAddr');
        const copyGeneratedBech32Addr = $('copyGeneratedBech32Addr');
        if (copyGeneratedLegacyAddr) copyGeneratedLegacyAddr.onclick = () => copyToClipboard('generatedLegacyAddress');
        if (copyGeneratedP2shAddr) copyGeneratedP2shAddr.onclick = () => copyToClipboard('generatedP2shAddress');
        if (copyGeneratedBech32Addr) copyGeneratedBech32Addr.onclick = () => copyToClipboard('generatedBech32Address');

        const revealHex = $('revealHex');
        const revealWif = $('revealWif');
        if (revealHex) {
          revealHex.onclick = () => {
            revealHex.disabled = true;
            $('privateKeyHex').classList.remove('blurred');
            setTimeout(() => {
              $('privateKeyHex').classList.add('blurred');
              revealHex.disabled = false;
            }, 10000);
          };
        }
        if (revealWif) {
          revealWif.onclick = () => {
            revealWif.disabled = true;
            $('privateKey').classList.remove('blurred');
            setTimeout(() => {
              $('privateKey').classList.add('blurred');
              revealWif.disabled = false;
            }, 10000);
          };
        }

        // Incrémenter le compteur après la génération réussie
        await incrementCounter();
        // Mettre à jour l'affichage du compteur
        await updateCounterDisplay();
      } catch (e) {
        alert(i18next.t('errors.generation_error', { message: e.message }));
        console.error('Generation error:', e);
      }
    };

    $('importWalletButton').onclick = async () => {
      updateLastActionTime();
      try {
        const wif = $('privateKeyWIF').value.trim();
        if (!wif) {
          alert(i18next.t('errors.import_empty'));
          return;
        }
        const addresses = /^[0-9a-fA-F]{64}$/.test(wif) ? importHex(wif) : importWIF(wif);

        if (!await validateAddress(addresses.legacy) ||
            !await validateAddress(addresses.p2sh) ||
            !await validateAddress(addresses.bech32)) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        legacyAddress = addresses.legacy;
        p2shAddress = addresses.p2sh;
        bech32Address = addresses.bech32;
        walletAddress = bech32Address;
        walletPublicKey = addresses.publicKey;
        walletKeyPair = addresses.keyPair;
        const legacyBalance = await balance(legacyAddress);
        const p2shBalance = await balance(p2shAddress);
        const bech32Balance = await balance(addresses.bech32);
        const totalBalance = legacyBalance + p2shBalance + bech32Balance;
        $('walletAddress').innerHTML = DOMPurify.sanitize(`
          Legacy: <span id="legacyAddress">${legacyAddress}</span> <button class="copy-btn" id="copyLegacyAddr">📋</button> (Solde: ${legacyBalance.toFixed(8)} NITO)<br>
          P2SH: <span id="p2shAddress">${p2shAddress}</span> <button class="copy-btn" id="copyP2shAddr">📋</button> (Solde: ${p2shBalance.toFixed(8)} NITO)<br>
          Bech32: <span id="bech32Address">${addresses.bech32}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (Solde: ${bech32Balance.toFixed(8)} NITO)
        `);
        $('walletBalance').textContent = totalBalance.toFixed(8);
        console.log('Wallet imported:', addresses);

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

        const copyLegacyAddr = $('copyLegacyAddr');
        const copyP2shAddr = $('copyP2shAddr');
        const copyBech32Addr = $('copyBech32Addr');
        if (copyLegacyAddr) copyLegacyAddr.onclick = () => copyToClipboard('legacyAddress');
        if (copyP2shAddr) copyP2shAddr.onclick = () => copyToClipboard('p2shAddress');
        if (copyBech32Addr) copyBech32Addr.onclick = () => copyToClipboard('bech32Address');

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
      } catch (e) {
        alert(i18next.t('errors.import_error', { message: e.message }));
        console.error('Import error:', e);
      }
    };

    $('refreshBalanceButton').onclick = async () => {
      updateLastActionTime();
      if (!walletAddress) return alert(i18next.t('errors.import_first'));
      try {
        const legacyBalance = await balance(legacyAddress);
        const p2shBalance = await balance(p2shAddress);
        const bech32Balance = await balance(bech32Address);
        const totalBalance = legacyBalance + p2shBalance + bech32Balance;

        if (!await validateAddress(legacyAddress) ||
            !await validateAddress(p2shAddress) ||
            !await validateAddress(bech32Address)) {
          throw new Error(i18next.t('errors.invalid_addresses'));
        }

        const safeLegacy = legacyAddress;
        const safeP2sh = p2shAddress;
        const safeBech32 = bech32Address;
        $('walletAddress').innerHTML = DOMPurify.sanitize(`
          Legacy: <span id="legacyAddress">${safeLegacy}</span> <button class="copy-btn" id="copyLegacyAddr">📋</button> (Solde: ${legacyBalance.toFixed(8)} NITO)<br>
          P2SH: <span id="p2shAddress">${safeP2sh}</span> <button class="copy-btn" id="copyP2shAddr">📋</button> (Solde: ${p2shBalance.toFixed(8)} NITO)<br>
          Bech32: <span id="bech32Address">${safeBech32}</span> <button class="copy-btn" id="copyBech32Addr">📋</button> (Solde: ${bech32Balance.toFixed(8)} NITO)
        `);
        $('walletBalance').textContent = totalBalance.toFixed(8);

        const copyLegacyAddr = $('copyLegacyAddr');
        const copyP2shAddr = $('copyP2shAddr');
        const copyBech32Addr = $('copyBech32Addr');
        if (copyLegacyAddr) copyLegacyAddr.onclick = () => copyToClipboard('legacyAddress');
        if (copyP2shAddr) copyP2shAddr.onclick = () => copyToClipboard('p2shAddress');
        if (copyBech32Addr) copyBech32Addr.onclick = () => copyToClipboard('bech32Address');
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
        const sourceType = $('debitAddressType').value;
        const destType = getAddressType(dest);
        let hex;
        if (sourceType === 'bech32' && destType === 'p2wpkh') {
          walletAddress = bech32Address;
          hex = await signTx(dest, amt);
        } else {
          walletAddress = sourceType === 'legacy' ? legacyAddress : sourceType === 'p2sh' ? p2shAddress : bech32Address;
          hex = await signTxWithPSBT(dest, amt);
        }
        $('signedTx').textContent = hex;
        $('txHexContainer').style.display = 'block';
        alert(i18next.t('OK.transaction_prepared'));
      } catch (e) {
        alert(i18next.t('errors.transaction_error', { message: e.message }));
        console.error('Transaction preparation error:', e);
      }
    };

    $('broadcastTxButton').onclick = async () => {
      updateLastActionTime();
      const hex = $('signedTx').textContent.trim();
      if (!hex) return alert(i18next.t('errors.no_transaction'));
      try {
        const txid = await rpc('sendrawtransaction', [hex]);
        await showSuccessPopup(txid);
        $('destinationAddress').value = '';
        $('amountNito').value = '';
        $('signedTx').textContent = '';
        setTimeout(() => $('refreshBalanceButton').click(), 3000);
      } catch (e) {
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
