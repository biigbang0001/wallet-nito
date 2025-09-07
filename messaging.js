import { Buffer } from 'https://esm.sh/buffer@6.0.3';
import * as bitcoin from 'https://esm.sh/bitcoinjs-lib@6.1.5?bundle';
import * as secp256k1 from 'https://esm.sh/@noble/secp256k1@2.1.0';

const MESSAGING_CONFIG = {
  CHUNK_SIZE: 40,
  MESSAGE_PREFIX: 'N_',
  PUBKEY_PREFIX: 'NITO_PUB_',
  COMPRESSION_LEVEL: 9,
  MESSAGE_FEE: 0.00000294,
  MAX_MESSAGE_LENGTH: 50000,
  PROTECTION_LIMIT: 0.00005
};

let walletData = {
  keyPair: null,
  publicKey: null,
  bech32Address: null,
  rpcFunction: null,
  isInitialized: false
};

class NitoMessaging {
  async getEffectiveFeeRate() {
    try {
      const [info, net, est] = await Promise.all([
        window.rpc('getmempoolinfo', []),
        window.rpc('getnetworkinfo', []),
        window.rpc('estimatesmartfee', [2]).catch(() => null)
      ]);
      const cfg = window.DYNAMIC_FEE_RATE || 0.00001;
      const nodeMin = Math.max((info && info.mempoolminfee) || 0, (net && net.relayfee) || 0);
      const estRate = (est && est.feerate) ? est.feerate : 0;
      return Math.max(cfg, nodeMin, estRate);
    } catch (e) {
      return window.DYNAMIC_FEE_RATE || 0.00001;
    }
  }

  constructor() {
    this.messageCache = new Map();
    this.deletedMessages = new Set();
    this.usedUtxos = new Set();
  }

  markUtxoAsUsed(txid, vout) {
    const utxoId = `${txid}:${vout}`;
    this.usedUtxos.add(utxoId);
    console.log(`🔒 UTXO réservé: ${utxoId}`);
  }

  releaseUtxo(txid, vout) {
    const utxoId = `${txid}:${vout}`;
    this.usedUtxos.delete(utxoId);
    console.log(`🔓 UTXO libéré: ${utxoId}`);
  }

  async initialize() {
    if (window.walletKeyPair && window.walletPublicKey && window.bech32Address && window.rpc) {
      walletData.keyPair = window.walletKeyPair;
      walletData.publicKey = window.walletPublicKey;
      walletData.bech32Address = window.bech32Address;
      walletData.isInitialized = true;
      console.log('🔒 Messagerie initialisée pour:', walletData.bech32Address);
      return true;
    }
    return false;
  }

  checkInitialized() {
    if (!walletData.isInitialized) {
    throw new Error(i18next.t('errors.wallet_not_initialized'));
    }
  }

  async deriveSharedKey(myPrivateKey, theirPublicKey) {
    try {
      console.log('🔑 Calcul ECDH avec noble-secp256k1...');

      if (!myPrivateKey || !theirPublicKey) {
        throw new Error('Clés manquantes pour ECDH');
      }

      const privateKeyHex = Buffer.from(myPrivateKey).toString('hex');
      const publicKeyHex = Buffer.from(theirPublicKey).toString('hex');

      if (!secp256k1.utils.isValidPrivateKey(privateKeyHex)) {
        throw new Error('Clé privée invalide');
      }

      const sharedPoint = secp256k1.getSharedSecret(privateKeyHex, publicKeyHex, true);

      const hashBuffer = await crypto.subtle.digest('SHA-256', sharedPoint);
      const derivedKey = new Uint8Array(hashBuffer);

      console.log('✅ Clé ECDH dérivée avec succès');
      return derivedKey;

    } catch (error) {
      console.error('❌ Erreur ECDH:', error);
      throw new Error(`Erreur dérivation clé partagée: ${error.message}`);
    }
  }

  async encryptWithAES(data, key) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key.slice(0, 32),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      const dataBuffer = new TextEncoder().encode(data);
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        dataBuffer
      );

      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encrypted), iv.length);

      const base64Result = btoa(String.fromCharCode(...result));

      console.log('✅ Chiffrement AES-GCM réussi');
      return base64Result;

    } catch (error) {
      console.error('❌ Erreur chiffrement AES:', error);
      throw new Error(`Erreur chiffrement: ${error.message}`);
    }
  }

  async decryptWithAES(encryptedData, key) {
    try {
      const encrypted = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));

      const iv = encrypted.slice(0, 12);
      const ciphertext = encrypted.slice(12);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key.slice(0, 32),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        ciphertext
      );

      const result = new TextDecoder().decode(decrypted);

      console.log('✅ Déchiffrement AES-GCM réussi');
      return result;

    } catch (error) {
      console.error('❌ Erreur déchiffrement AES:', error);
      throw new Error(`Erreur déchiffrement: ${error.message}`);
    }
  }

  async createOpReturnTransaction(toAddress, amount, opReturnData, specificUtxo) {
    this.checkInitialized();

    try {
      if (!specificUtxo) {
        throw new Error("UTXO spécifique requis");
      }

      const target = Math.round(amount * 1e8);
      const feeRate = await this.getEffectiveFeeRate();
      const txSize = 250;
      const fees = Math.round(txSize * (feeRate * 1e8) / 1000);
      const total = Math.round(specificUtxo.amount * 1e8);
      const change = total - target - fees;

      if (change < 0) throw new Error('Fonds insuffisants');

      const psbt = new bitcoin.Psbt({ network: this.getNetworkConfig() });
      psbt.setVersion(2);

      const scriptBuffer = Buffer.from(specificUtxo.scriptPubKey, 'hex');
      psbt.addInput({
        hash: specificUtxo.txid,
        index: specificUtxo.vout,
        witnessUtxo: { script: scriptBuffer, value: total }
      });

      psbt.addOutput({ address: toAddress, value: target });

      if (opReturnData) {
        const dataBuffer = Buffer.from(opReturnData, 'utf8');
        if (dataBuffer.length > 75) {
          throw new Error('Données OP_RETURN trop volumineuses');
        }

        const opReturnScript = bitcoin.script.compile([
          bitcoin.opcodes.OP_RETURN,
          dataBuffer
        ]);

        psbt.addOutput({ script: opReturnScript, value: 0 });
      }

      if (change > 294) {
        psbt.addOutput({ address: walletData.bech32Address, value: change });
      }

      const signer = {
        network: walletData.keyPair.network,
        privateKey: walletData.keyPair.privateKey,
        publicKey: walletData.publicKey,
        sign: (hash) => Buffer.from(walletData.keyPair.sign(hash))
      };

      psbt.signInput(0, signer, [bitcoin.Transaction.SIGHASH_ALL]);
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();
      return tx.toHex();

    } catch (error) {
      console.error('Erreur création transaction OP_RETURN:', error);
      throw error;
    }
  }

  async publishPublicKey() {
    this.checkInitialized();

    try {
      const publicKeyHex = Buffer.from(walletData.publicKey).toString('hex');
      const opReturnData = `NITOPUB:${publicKeyHex}`;

      console.log('Publication clé publique...');

      let availableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
      availableUtxos = availableUtxos.filter(utxo => utxo.amount >= 0.000003);
      if (availableUtxos.length === 0) {
        throw new Error('Aucun UTXO disponible pour publier la clé publique');
      }

      const hex = await this.createOpReturnTransaction(
        walletData.bech32Address,
        MESSAGING_CONFIG.MESSAGE_FEE,
        opReturnData,
        availableUtxos[0]
      );

      const txid = await window.rpc('sendrawtransaction', [hex]);

      console.log('✅ Clé publique publiée, TXID:', txid);

      if (window.showSuccessPopup) {
        await window.showSuccessPopup(txid);
      }

      return { success: true, txid, publicKey: publicKeyHex };
    } catch (error) {
      console.error('❌ Erreur publication clé publique:', error);
      throw new Error(`Erreur publication: ${error.message}`);
    }
  }

  async findPublicKey(bech32Address) {
    try {
      if (!bech32Address || bech32Address === "null" || bech32Address === "unknown_sender") {
        console.log("❌ Adresse invalide ou inconnue:", bech32Address);
        return null;
      }

      console.log("🔍 Recherche clé publique pour:", bech32Address);

      const scan = await window.rpc("scantxoutset", ["start", [`addr(${bech32Address})`]]);

      if (!scan.unspents) {
        console.log("❌ Aucune transaction trouvée pour:", bech32Address);
        return null;
      }

      console.log(`🔍 Analyse de ${scan.unspents.length} UTXOs pour trouver la clé publique`);

      for (const utxo of scan.unspents) {
        try {
           const tx = await window.rpc("getrawtransaction", [utxo.txid, true]);

          for (const output of tx.vout) {
            if (output.scriptPubKey && output.scriptPubKey.hex) {
              const opReturnData = this.extractOpReturnData(output.scriptPubKey.hex);

              if (opReturnData && opReturnData.startsWith("NITOPUB:")) {
                const publicKeyHex = opReturnData.substring(8);

                if (publicKeyHex.length === 66 || publicKeyHex.length === 64) {
                  const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");
                  console.log("✅ CLÉ PUBLIQUE TROUVÉE ET VALIDÉE pour:", bech32Address);
                  return publicKeyBuffer;
                }
              }
            }
          }
        } catch (e) {
          console.warn(`⚠️ Erreur analyse transaction ${utxo.txid}:`, e.message);
        }
      }

      console.log("❌ Aucune clé publique trouvée pour:", bech32Address);
      return null;
    } catch (error) {
      console.error("❌ Erreur recherche clé publique:", error);
      throw error;
    }
  }

  async encryptMessage(message, recipientBech32Address) {
    this.checkInitialized();

    try {
      console.log("🔐 Chiffrement ECDH pour:", recipientBech32Address);

      const recipientPublicKey = await this.findPublicKey(recipientBech32Address);
      if (!recipientPublicKey) {
        throw new Error('Clé publique du destinataire introuvable. Le destinataire doit d\'abord publier sa clé publique.');
      }

      console.log("✅ Clé publique destinataire trouvée");

      const messageData = {
        content: message,
        sender: walletData.bech32Address,
        recipient: recipientBech32Address,
        timestamp: Date.now(),
        messageId: this.generateMessageId()
      };

      const messageJson = JSON.stringify(messageData);

      const sharedKey = await this.deriveSharedKey(
        walletData.keyPair.privateKey,
        recipientPublicKey
      );

      const encryptedMessage = await this.encryptWithAES(messageJson, sharedKey);

      const signature = await this.hashMessage(messageData.messageId + messageData.timestamp + walletData.bech32Address);

      const finalMessage = {
        data: encryptedMessage,
        signature: signature,
        messageId: messageData.messageId,
        timestamp: messageData.timestamp,
        sender: walletData.bech32Address,
        recipient: recipientBech32Address,
        senderPublicKey: Buffer.from(walletData.publicKey).toString('hex'),
        recipientPublicKey: Buffer.from(recipientPublicKey).toString('hex')
      };

      console.log("✅ Message chiffré avec ECDH + AES-GCM");
      return JSON.stringify(finalMessage);

    } catch (error) {
      console.error('❌ Erreur chiffrement ECDH:', error);
      throw error;
    }
  }

  async decryptMessage(encryptedMessage, senderAddress) {
    this.checkInitialized();

    try {
      console.log("🔓 Déchiffrement ECDH pour:", walletData.bech32Address);

      if (!encryptedMessage || typeof encryptedMessage !== 'string') {
        throw new Error("Message vide ou invalide");
      }

      let messageEnvelope;
      try {
        messageEnvelope = JSON.parse(encryptedMessage);
      } catch (e) {
        throw new Error("Format de message invalide");
      }

      if (messageEnvelope.recipient !== walletData.bech32Address) {
        throw new Error("Ce message ne vous est pas destiné");
      }

      let senderPublicKey;
      if (messageEnvelope.senderPublicKey) {
        senderPublicKey = Buffer.from(messageEnvelope.senderPublicKey, 'hex');
        console.log("✅ Clé publique incluse utilisée - pas de scan blockchain");
      } else {
        // Fallback pour anciens messages
        senderPublicKey = await this.findPublicKey(messageEnvelope.sender);
        if (!senderPublicKey) {
          throw new Error("Impossible de trouver la clé publique de l'expéditeur");
        }
      }

      console.log("✅ Clé publique expéditeur trouvée");

      const sharedKey = await this.deriveSharedKey(
        walletData.keyPair.privateKey,
        senderPublicKey
      );

      const decryptedJson = await this.decryptWithAES(messageEnvelope.data, sharedKey);

      let decryptedMessage;
      try {
        decryptedMessage = JSON.parse(decryptedJson);
      } catch (e) {
        throw new Error("Erreur parsing message déchiffré");
      }

      const expectedSignature = await this.hashMessage(
        decryptedMessage.messageId +
        decryptedMessage.timestamp +
        decryptedMessage.sender
      );
      const verified = expectedSignature === messageEnvelope.signature;

      console.log("✅ Déchiffrement ECDH terminé, message vérifié:", verified);

      return {
        ...decryptedMessage,
        verified
      };

    } catch (error) {
      console.error("❌ Erreur déchiffrement ECDH:", error);
      throw error;
    }
  }

  async hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async prepareUtxosForMessage(chunksNeeded) {
  console.log(`🔧 Préparation de ${chunksNeeded} UTXOs optimisés pour messagerie...`);

  let availableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
  availableUtxos = availableUtxos.filter(utxo => utxo.amount >= 0.000003);
  if (availableUtxos.length === 0) {
    throw new Error('Aucun UTXO disponible pour la préparation');
  }

  // Calculer les fees exacts basés sur la taille de transaction
  const estimatedInputs = 1; // Un input (le gros UTXO)
  const estimatedOutputs = chunksNeeded + 1; // Tous les petits UTXOs + change
  const estimatedTxSize = (estimatedInputs * 148) + (estimatedOutputs * 34) + 10; // Taille estimée en bytes

  console.log(`📏 Transaction estimée: ${estimatedTxSize} bytes pour ${chunksNeeded} UTXOs`);

  const feeRate = await this.getEffectiveFeeRate();
  const preparationFeesInSatoshis = Math.round(estimatedTxSize * (feeRate * 1e8) / 1000);
  const preparationFeeRate = preparationFeesInSatoshis / 1e8;

  console.log(`💰 Frais préparation split: ${preparationFeesInSatoshis} satoshis (${preparationFeeRate.toFixed(8)} NITO)`);
const perChunkVBytes = 250;
const perChunkFeesSat = Math.ceil(perChunkVBytes * ((feeRate * 1e8) / 1000));
const perChunkFeesCoin = perChunkFeesSat / 1e8;
  console.log(`🧩 Frais estimés par chunk: ${perChunkFeesSat} satoshis (${perChunkFeesCoin.toFixed(8)} NITO)`);
const amountPerUtxo = (MESSAGING_CONFIG.MESSAGE_FEE + perChunkFeesCoin) * 1.2;
console.log(`💰 UTXOs adaptatifs: ${amountPerUtxo.toFixed(8)} NITO`);
  const totalNeeded = chunksNeeded * amountPerUtxo;

  const biggestUtxo = availableUtxos[0];
  if (biggestUtxo.amount < totalNeeded) {
    throw new Error(`UTXO insuffisant. Requis: ${totalNeeded}, Disponible: ${biggestUtxo.amount}`);
  }

  console.log(`💰 Création de ${chunksNeeded} UTXOs de ${amountPerUtxo} NITO chacun`);

  // Créer une transaction qui split le gros UTXO en plein de petits
  const psbt = new bitcoin.Psbt({ network: this.getNetworkConfig() });
  psbt.setVersion(2);

  const scriptBuffer = Buffer.from(biggestUtxo.scriptPubKey, 'hex');
  const total = Math.round(biggestUtxo.amount * 1e8);

  psbt.addInput({
    hash: biggestUtxo.txid,
    index: biggestUtxo.vout,
    witnessUtxo: { script: scriptBuffer, value: total }
  });

  // Créer tous les petits outputs
  const outputAmount = Math.round(amountPerUtxo * 1e8);
  for (let i = 0; i < chunksNeeded; i++) {
    psbt.addOutput({ address: walletData.bech32Address, value: outputAmount });
  }

  // Change restant
  const usedAmount = chunksNeeded * outputAmount;
  const fees = Math.round(preparationFeeRate * 1e8);
  const change = total - usedAmount - fees;

  if (change > 294) {
    psbt.addOutput({ address: walletData.bech32Address, value: change });
  }

  const signer = {
    network: walletData.keyPair.network,
    privateKey: walletData.keyPair.privateKey,
    publicKey: walletData.publicKey,
    sign: (hash) => Buffer.from(walletData.keyPair.sign(hash))
  };

  psbt.signInput(0, signer, [bitcoin.Transaction.SIGHASH_ALL]);
  psbt.finalizeAllInputs();

  const tx = psbt.extractTransaction();
  const txid = await window.rpc('sendrawtransaction', [tx.toHex()]);

  console.log(`✅ UTXOs préparés, TXID: ${txid}`);

  console.log('⏳ Attente des nouveaux UTXOs...');

  const MAX_WAIT_TIME = 3600000;
  const CHECK_INTERVAL = 6000;
  const EXPECTED_BLOCK_TIME = 120000;

  let elapsedTime = 0;
  let found = false;

  while (elapsedTime < MAX_WAIT_TIME && !found) {
    // Calculer le pourcentage basé sur le temps de bloc attendu
    const progressBasedOnTime = Math.min(100, (elapsedTime / EXPECTED_BLOCK_TIME) * 100);

    // Mettre à jour l'affichage avec le pourcentage animé
    this.updateProgressIndicator(0, 1, i18next.t('progress_indicators.preparing_utxos_percentage', { percentage: Math.round(progressBasedOnTime) }));

    console.log(`🔍 Attente ${Math.round(elapsedTime/1000)}s - Progression: ${Math.round(progressBasedOnTime)}%`);

    // Attendre 6 secondes
    await this.delay(CHECK_INTERVAL);
    elapsedTime += CHECK_INTERVAL;

    // Vérifier si les UTXOs sont disponibles
    const newUtxos = await this.getAvailableUtxos(walletData.bech32Address);
    const smallUtxos = newUtxos
      .filter(u => u.amount > MESSAGING_CONFIG.MESSAGE_FEE && u.amount <= 0.01)
      .sort((a, b) => a.amount - b.amount);

    console.log(`🔍 ${Math.round(elapsedTime/1000)}s: ${smallUtxos.length} petits UTXOs trouvés`);

    if (smallUtxos.length >= chunksNeeded) {
      console.log(`✅ ${smallUtxos.length} UTXOs optimisés disponibles !`);
      found = true;
      // Afficher 100% une fois trouvé
      this.updateProgressIndicator(1, 1, i18next.t('progress_indicators.preparation_complete'));
      await this.delay(1000); // Laisser voir le 100%
      return txid;
    }

    // Si on dépasse 60s, indiquer que c'est plus long que prévu
    if (elapsedTime > EXPECTED_BLOCK_TIME && elapsedTime < EXPECTED_BLOCK_TIME + CHECK_INTERVAL) {
      console.log('⚠️ Bloc plus lent que prévu, attente prolongée...');
    }

    // Messages informatifs à intervalles réguliers
    if (elapsedTime % 300000 === 0 && elapsedTime > 0) { // Toutes les 5 minutes
      console.log(`⏰ Attente en cours: ${Math.round(elapsedTime/60000)} minutes écoulées`);
    }
  }

  if (!found) {
    throw new Error(`Timeout: nouveaux UTXOs non confirmés après 60 minutes`);
  }
}

  async getChangeUtxo(txid) {
    try {
      await this.delay(5000);

      const tx = await window.rpc('getrawtransaction', [txid, true]);

      for (let i = 0; i < tx.vout.length; i++) {
        const output = tx.vout[i];
        if (output.scriptPubKey &&
            output.scriptPubKey.address === walletData.bech32Address &&
            output.value >= MESSAGING_CONFIG.MESSAGE_FEE * 2) {

          return {
            txid: txid,
            vout: i,
            amount: output.value,
            scriptPubKey: output.scriptPubKey.hex,
            id: `${txid}:${i}`
          };
        }
      }

      throw new Error('Change UTXO non trouvé ou insuffisant');
    } catch (error) {
      console.error('❌ Erreur récupération change UTXO:', error);
      throw error;
    }
  }

  updateProgressIndicator(current, total, action = 'Envoi') {
    const progressElement = document.getElementById('messageProgress');
    if (progressElement) {
      const percentage = Math.round((current / total) * 100);
      progressElement.innerHTML = `
        <div style="margin: 10px 0; padding: 15px; background: #f0f0f0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
          <div style="margin-bottom: 8px; font-weight: bold; color: #333;">${action}: ${current}/${total} chunks (${percentage}%)</div>
          <div style="width: 100%; background: #ddd; border-radius: 10px; height: 20px; overflow: hidden;">
            <div style="width: ${percentage}%; background: linear-gradient(90deg, #4b5e40, #6b7e60); height: 20px; border-radius: 10px; transition: width 0.3s ease;"></div>
          </div>
        </div>
      `;
    }
  }

  showScanProgress(current, total) {
    const progressElement = document.getElementById('messageProgress');
    if (progressElement) {
      const percentage = Math.round((current / total) * 100);
      progressElement.innerHTML = `
        <div style="text-align: center;">
          <div style="margin-bottom: 10px; font-weight: bold;">${i18next.t('progress_indicators.analyzing_messages')}</div>
          <div style="margin-bottom: 5px;">${current}/${total} ${i18next.t('progress_indicators.transactions')} (${percentage}%)</div>
          <div style="width: 300px; background: #ddd; border-radius: 10px; height: 20px;">
            <div style="width: ${percentage}%; background: #4b5e40; height: 20px; border-radius: 10px; transition: width 0.3s;"></div>
          </div>
        </div>
      `;
    }
  }

  
  async isInboundMessageUtxo(utxo) {
    try {
      const tx = await window.rpc('getrawtransaction', [utxo.txid, true]);
      const hasMsg = (tx.vout || []).some(v => {
        const hex = v.scriptPubKey && v.scriptPubKey.hex;
        if (!hex) return false;
        const data = this.extractOpReturnData(hex);
        return !!(data && data.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX));
      });
      return !!hasMsg;
    } catch (e) {
      return false;
    }
  }
async sendMessage(message, recipientBech32Address) {
    this.checkInitialized();

    try {
      console.log("📤 Envoi message vers:", recipientBech32Address);

      this.updateProgressIndicator(0, 1, i18next.t('progress_indicators.preparing'));

      const encryptedMessage = await this.encryptMessage(message, recipientBech32Address);
      const chunks = this.splitIntoChunks(encryptedMessage, MESSAGING_CONFIG.CHUNK_SIZE);
      const messageId = JSON.parse(encryptedMessage).messageId;

      console.log(`📦 Message divisé en ${chunks.length} chunks`);

      let availableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
      const estTxVBytes = 250;
      const feeRate = await this.getEffectiveFeeRate();
      const estFee = (estTxVBytes * (feeRate * 1e8) / 1000) / 1e8;
      const minFunding = (MESSAGING_CONFIG.MESSAGE_FEE + estFee) * 1.2;
      const candidates = availableUtxos.filter(u => u.amount >= minFunding);
      const tagged = await Promise.all(candidates.map(async u => ({ u, inbound: await this.isInboundMessageUtxo(u) })));
      availableUtxos = tagged.filter(t => !t.inbound).map(t => t.u);
      if (availableUtxos.length < chunks.length) {
        console.log(`⚠️ Préparation de ${chunks.length} UTXOs optimisés...`);
        await this.prepareUtxosForMessage(chunks.length);

        // Recharger les UTXOs après préparation
        await this.delay(2000);
        availableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
        const estTxVBytes = 250;
      const feeRate = await this.getEffectiveFeeRate();
      const estFee = (estTxVBytes * (feeRate * 1e8) / 1000) / 1e8;
      const minFunding = (MESSAGING_CONFIG.MESSAGE_FEE + estFee) * 1.2;
      const candidates = availableUtxos.filter(u => u.amount >= minFunding);
      const tagged = await Promise.all(candidates.map(async u => ({ u, inbound: await this.isInboundMessageUtxo(u) })));
      availableUtxos = tagged.filter(t => !t.inbound).map(t => t.u);
      }

      if (availableUtxos.length === 0) {
        throw new Error('Aucun UTXO viable disponible');
      }

      let transactions = [];

      try {
        // Récupérer TOUS les UTXOs disponibles
        let allAvailableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
        const estTxVBytes2 = 250;
        const feeRate2 = await this.getEffectiveFeeRate();
        const estFee2 = (estTxVBytes2 * (feeRate2 * 1e8) / 1000) / 1e8;
        const minFunding2 = (MESSAGING_CONFIG.MESSAGE_FEE + estFee2) * 1.2;
        const candidates2 = allAvailableUtxos.filter(u => u.amount >= minFunding2);
        const tagged2 = await Promise.all(candidates2.map(async u => ({ u, inbound: await this.isInboundMessageUtxo(u) })));
        allAvailableUtxos = tagged2.filter(t => !t.inbound).map(t => t.u);
        console.log(i18next.t('messaging_debug.available_utxos', { count: allAvailableUtxos.length }));

        // Réserver tous les UTXOs qu'on va utiliser
        const utxosToUse = allAvailableUtxos.slice(0, Math.min(chunks.length, allAvailableUtxos.length));
        utxosToUse.forEach(utxo => this.markUtxoAsUsed(utxo.txid, utxo.vout));

        console.log(i18next.t('messaging_debug.parallel_sending', { utxos: utxosToUse.length, chunks: chunks.length }));

        // Créer toutes les transactions en parallèle
        const transactionPromises = [];

        for (let i = 0; i < chunks.length; i++) {
          const opReturnData = `${MESSAGING_CONFIG.MESSAGE_PREFIX}${messageId}_${i}_${chunks.length}_${chunks[i]}`;
          const utxoIndex = i % utxosToUse.length; // Rotation des UTXOs si plus de chunks que d'UTXOs
          const selectedUtxo = utxosToUse[utxoIndex];

          console.log(`🚀 Préparation chunk ${i + 1}/${chunks.length} avec UTXO ${selectedUtxo.amount} NITO`);

          // Créer la transaction
          const transactionPromise = this.createOpReturnTransaction(
            recipientBech32Address,
            MESSAGING_CONFIG.MESSAGE_FEE,
            opReturnData,
            selectedUtxo
          ).then(hex => ({
            chunkIndex: i,
            hex: hex,
            utxo: selectedUtxo
          }));

          transactionPromises.push(transactionPromise);
        }

        // Attendre que toutes les transactions soient créées
        console.log(i18next.t('messaging_debug.creating_transactions'));
        const preparedTransactions = await Promise.all(transactionPromises);
        console.log(i18next.t('messaging_debug.transactions_prepared'));

        // Envoyer les transactions par lots avec retry automatique
        const BATCH_SIZE = 100;
        const results = [];
        let pendingTransactions = [...preparedTransactions];

        while (pendingTransactions.length > 0) {
          const batch = pendingTransactions.slice(0, BATCH_SIZE);
          const currentBatch = Math.ceil((preparedTransactions.length - pendingTransactions.length + batch.length) / BATCH_SIZE);
          const totalBatches = Math.ceil(preparedTransactions.length / BATCH_SIZE);

          console.log(`📤 Lot ${currentBatch}/${totalBatches}: ${batch.length} transactions (${pendingTransactions.length} restantes)`);

          // Envoyer ce lot en parallèle avec retry
          const batchPromises = batch.map(async (transaction) => {
            let attempts = 0;
            const maxAttempts = 10; // Maximum 10 tentatives par chunk

            while (attempts < maxAttempts) {
              try {
                this.updateProgressIndicator(
                  preparedTransactions.length - pendingTransactions.length + 1, 
                  preparedTransactions.length, 
                  `Envoi (tentative ${attempts + 1})`
                );

                const txid = await window.rpc("sendrawtransaction", [transaction.hex]);
                console.log(`✅ Chunk ${transaction.chunkIndex + 1}/${chunks.length} envoyé: ${txid}`);

                return {
                  success: true,
                  txid: txid,
                  chunkIndex: transaction.chunkIndex,
                  transaction: transaction
                };
              } catch (error) {
                attempts++;
        
                if (error.message.includes("already in block chain")) {
                  // Transaction déjà confirmée = succès !
                  console.log(`✅ Chunk ${transaction.chunkIndex + 1} déjà confirmé`);
                  return {
                    success: true,
                    txid: "already_confirmed",
                    chunkIndex: transaction.chunkIndex,
                    transaction: transaction
                  };
                }

                console.warn(`⚠️ Tentative ${attempts}/${maxAttempts} échouée pour chunk ${transaction.chunkIndex + 1}: ${error.message}`);
        
                if (attempts < maxAttempts) {
                  // Attendre entre 1 et 3 secondes avant retry
                  const delayMs = Math.floor(Math.random() * 2000) + 1000;
                  await this.delay(delayMs);
                }
              }
            }

            // Si toutes les tentatives ont échoué
            console.error(`❌ Chunk ${transaction.chunkIndex + 1} abandonné après ${maxAttempts} tentatives`);
            return {
              success: false,
              error: "Max attempts reached",
              chunkIndex: transaction.chunkIndex,
              transaction: transaction
            };
          });

          const batchResults = await Promise.all(batchPromises);
  
          // Séparer les succès des échecs
          const successes = batchResults.filter(r => r.success);
          const failures = batchResults.filter(r => !r.success);
  
          results.push(...successes);
  
          // Retirer les transactions réussies de la liste pending
          pendingTransactions = pendingTransactions.filter(t => 
            !successes.some(s => s.chunkIndex === t.chunkIndex)
          );
  
          console.log(`✅ Lot ${currentBatch} terminé: ${successes.length} succès, ${failures.length} échecs, ${pendingTransactions.length} restantes`);
  
          // Pause entre les lots si il en reste
          if (pendingTransactions.length > 0) {
            const delayMs = Math.floor(Math.random() * 2000) + 1000; // 1-3 secondes
            console.log(`⏸️ Pause ${delayMs}ms avant le prochain lot...`);
            await this.delay(delayMs);
          }
        }


        // Analyser les résultats
        const successfulResults = results.filter(r => r.success);
        const failedResults = results.filter(r => !r.success);

        console.log(i18next.t('messaging_debug.sending_complete', {
          successful: successfulResults.length,
          total: results.length
        }));

        if (failedResults.length > 0) {
          if (failedResults.length > 0) {
            console.warn(i18next.t('messaging_debug.failed_chunks'), failedResults.map(r => r.chunkIndex + 1));
          }
        }

        transactions = successfulResults.map(r => r.txid);

        // Libérer tous les UTXOs utilisés
        utxosToUse.forEach(utxo => this.releaseUtxo(utxo.txid, utxo.vout));

        const successfulChunks = transactions.length;
        console.log(`🎉 Message envoyé avec succès: ${successfulChunks}/${chunks.length} chunks`);

        const progressElement = document.getElementById('messageProgress');
        if (progressElement) {
          setTimeout(() => {
            progressElement.innerHTML = '';
          }, 3000);
        }

        // Utiliser showSuccessPopup du wallet.js avec le dernier txid
        const lastTxid = transactions[transactions.length - 1];
        if (window.showSuccessPopup && lastTxid) {
          await window.showSuccessPopup(lastTxid);
        }

        return {
          success: true,
          messageId,
          transactions,
          chunks: successfulChunks,
          totalChunks: chunks.length,
          totalCost: successfulChunks * MESSAGING_CONFIG.MESSAGE_FEE,
          efficient: successfulChunks === chunks.length,
          lastTxid: lastTxid
        };

      } catch (error) {
        // Libérer les UTXOs en cas d'erreur aussi
        if (typeof utxosToUse !== 'undefined') {
          utxosToUse.forEach(utxo => this.releaseUtxo(utxo.txid, utxo.vout));
        }
        throw error;
      }

    } catch (error) {
      console.error("❌ Erreur envoi message:", error);
      throw error;
    }
  }

  async scanInboxMessages() {
    this.checkInitialized();

    try {
      console.log('📬 Scan des messages pour:', walletData.bech32Address);

      const transactions = await this.getAddressTransactions(walletData.bech32Address);
      const messages = new Map();

      // Plus besoin de progression - tout est fait dans getAddressTransactions !
      for (const tx of transactions) {
        const opReturnData = tx.opReturnData; // ← Utiliser la donnée déjà récupérée

        if (opReturnData && opReturnData.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX)) {
          const messageData = opReturnData.substring(MESSAGING_CONFIG.MESSAGE_PREFIX.length);
          const parts = messageData.split('_');

          if (parts.length < 4) {
            console.warn("⚠️ Format de chunk invalide:", messageData);
            continue;
          }

          const [messageId, chunkIndex, totalChunks, ...chunkDataParts] = parts;
          const chunkData = chunkDataParts.join('_');

          if (this.deletedMessages.has(messageId)) continue;

          if (!messages.has(messageId)) {
            messages.set(messageId, {
              id: messageId,
              chunks: new Map(),
              totalChunks: parseInt(totalChunks),
              timestamp: tx.time || Date.now() / 1000,
              txid: tx.txid,
              senderAddress: tx.senderAddress  // ← Utiliser la donnée déjà récupérée
            });
          }

          const message = messages.get(messageId);
          const chunkIdx = parseInt(chunkIndex);

          if (chunkIdx >= 0 && chunkIdx < message.totalChunks && !message.chunks.has(chunkIdx)) {
            message.chunks.set(chunkIdx, chunkData);
            console.log(`📦 Chunk ${chunkIdx}/${message.totalChunks} reçu pour message ${messageId}`);
          } else if (message.chunks.has(chunkIdx)) {
            console.log(`⚠️ Chunk ${chunkIdx} déjà présent pour message ${messageId} - ignoré`);
          }
        }
      }

      const completeMessages = [];
      for (const [messageId, messageData] of messages) {
        if (messageData.chunks.size === messageData.totalChunks) {
          try {
            const sortedChunks = [];
            for (let i = 0; i < messageData.totalChunks; i++) {
              if (!messageData.chunks.has(i)) {
                throw new Error(`Chunk manquant à l'index ${i}`);
              }
              sortedChunks.push(messageData.chunks.get(i));
            }
            const encryptedMessage = sortedChunks.join('');
            console.log(`🔗 Message ${messageId} reconstitué, taille: ${encryptedMessage.length}`);

            try {
              const __env = JSON.parse(encryptedMessage);
              if (__env && __env.recipient && __env.recipient !== walletData.bech32Address) {
                console.log(`ℹ️ Message ${messageId} ignoré (destiné à ${__env.recipient})`);
                continue;
              }
            } catch (e) {}
            const decryptedMessage = await this.decryptMessage(encryptedMessage, messageData.senderAddress);
            completeMessages.push({
              id: messageId,
              content: decryptedMessage.content,
              sender: decryptedMessage.sender,
              timestamp: decryptedMessage.timestamp,
              status: 'unread',
              verified: decryptedMessage.verified,
              senderAddress: messageData.senderAddress
            });

          } catch (error) {
            if (error && error.message && /destiné/.test(error.message)) {
              console.log(`ℹ️ Message ${messageId} ignoré (non destiné à ${walletData.bech32Address}).`);
              continue;
            }
            console.error(`❌ Erreur déchiffrement message ${messageId}:`, error);

            let errorType = "Erreur de déchiffrement";
            if (error.message.includes("GCM")) {
              errorType = "Données corrompues";
            } else if (error.message.includes("JSON")) {
              errorType = "Format invalide";
            } else if (error.message.includes("destiné")) {
              errorType = "Message non destiné";
            } else if (error.message.includes("ECDH")) {
              errorType = "Erreur cryptographique";
            }

            completeMessages.push({
              id: messageId,
              content: `[Message illisible - ${errorType}: ${error.message}]`,
              sender: messageData.senderAddress,
              timestamp: messageData.timestamp,
              status: 'error',
              verified: false,
              senderAddress: messageData.senderAddress,
              errorDetails: error.message
            });
          }
        } else {
          console.log(`📦 Message ${messageId} incomplet: ${messageData.chunks.size}/${messageData.totalChunks} chunks`);
        }
      }

      return completeMessages.sort((a, b) => b.timestamp - a.timestamp);
    } catch (error) {
      console.error('❌ Erreur scan messages:', error);
      throw error;
    }
  }

  async consolidateMessagingUtxos() {
    this.checkInitialized();

    try {
      console.log('🔧 Consolidation des UTXOs de messagerie...');

      const availableUtxos = await this.getAvailableUtxos(walletData.bech32Address);
      if (availableUtxos.length < 2) {
        throw new Error('Pas assez d\'UTXOs pour consolider (minimum 2 requis)');
      }

      if (window.consolidateUtxos && typeof window.consolidateUtxos === 'function') {
        await window.consolidateUtxos();
        console.log('✅ Consolidation terminée via wallet principal');

        alert(i18next.t('errors.republish_public_key'));

        return { success: true, message: 'Consolidation terminée' };
      } else {
        throw new Error('Fonction de consolidation non disponible');
      }

    } catch (error) {
      console.error('❌ Erreur consolidation messagerie:', error);
      throw error;
    }
  }

  async getAddressTransactions(address) {
  try {
    console.log("🔍 Recherche transactions pour:", address);
    const scan = await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);

    if (scan.unspents) { scan.unspents = scan.unspents.filter(u => u.amount <= MESSAGING_CONFIG.PROTECTION_LIMIT); console.log(`📊 UTXOs protégés: ${scan.unspents.length}`); }

    const transactions = [];
    const uniqueTxids = [...new Set(scan.unspents?.map(utxo => utxo.txid) || [])];
    console.log(`🚀 Analyse complète de ${uniqueTxids.length} transactions par lots...`);

    const BATCH_SIZE = 20;

    for (let i = 0; i < uniqueTxids.length; i += BATCH_SIZE) {
      const batch = uniqueTxids.slice(i, i + BATCH_SIZE);
      const batchNumber = Math.floor(i/BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(uniqueTxids.length/BATCH_SIZE);

      console.log(`📥 Lot ${batchNumber}/${totalBatches}: ${batch.length} transactions`);

      // Mise à jour de la progression avec le vrai pourcentage
      this.showScanProgress(i + batch.length, uniqueTxids.length);

      const batchPromises = batch.map(async (txid) => {
        try {
          const txDetail = await window.rpc("getrawtransaction", [txid, true]);

          // TOUT FAIRE ICI EN UNE FOIS
          // 1. Extraire OP_RETURN
          let opReturnData = null;
          for (const output of txDetail.vout) {
            if (output.scriptPubKey && output.scriptPubKey.hex) {
              opReturnData = this.extractOpReturnData(output.scriptPubKey.hex);
              if (opReturnData) break;
            }
          }

          // 2. Extraire adresse expéditeur
          let senderAddress = "unknown_sender";
          if (txDetail.vin && txDetail.vin.length > 0) {
            const firstInput = txDetail.vin[0];
            if (firstInput.txid && firstInput.vout !== undefined) {
              try {
                const prevTx = await window.rpc('getrawtransaction', [firstInput.txid, true]);
                const prevOutput = prevTx.vout[firstInput.vout];
                if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.addresses) {
                  senderAddress = prevOutput.scriptPubKey.addresses[0];
                } else if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.address) {
                  senderAddress = prevOutput.scriptPubKey.address;
                }
              } catch (e) {
                // Garde "unknown_sender"
              }
            }
          }

          return {
            txid: txDetail.txid,
            time: txDetail.time || txDetail.blocktime || Date.now() / 1000,
            vout: txDetail.vout,
            vin: txDetail.vin,
            opReturnData: opReturnData,      // ← NOUVEAU
            senderAddress: senderAddress     // ← NOUVEAU
          };
        } catch (e) {
          console.warn(`⚠️ Transaction ${txid} inaccessible`);
          return null;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      const validResults = batchResults.filter(tx => tx !== null);
      transactions.push(...validResults);

      console.log(`✅ Lot ${batchNumber} terminé: ${validResults.length}/${batch.length} transactions analysées`);

      // Pause courte entre les lots
      if (i + BATCH_SIZE < uniqueTxids.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    
    
    try {
      const mempoolTxids = await window.rpc("getrawmempool", [false]);
      const MAX_MEMPOOL = 500; // limite pour éviter un scan trop lourd
      const poolTxids = mempoolTxids.slice(0, MAX_MEMPOOL);
      console.log(`📥 Mempool: analyse de ${poolTxids.length} transactions (limitées)`);

      const mempoolPromises = poolTxids.map(async (txid) => {
        try {
          const txDetail = await window.rpc("getrawtransaction", [txid, true]);

          // Vérifie qu’elle paie bien l’adresse cible
          const paysToAddress = (txDetail.vout || []).some(v =>
            (v.scriptPubKey?.address === address) ||
            (Array.isArray(v.scriptPubKey?.addresses) && v.scriptPubKey.addresses.includes(address))
          );
          if (!paysToAddress) return null;

          // Cherche un OP_RETURN avec le préfixe voulu (N_)
          let opReturnData = null;
          for (const v of txDetail.vout || []) {
            const hex = v.scriptPubKey?.hex;
            if (hex) {
              const data = this.extractOpReturnData(hex);
              if (data && data.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX)) {
                opReturnData = data;
                break;
              }
            }
          }
          if (!opReturnData) return null;

          const senderAddress = await this.getTransactionSenderAddress(txDetail.txid);

          return {
            txid: txDetail.txid,
            time: Date.now() / 1000, // pas confirmé => timestamp local
            vout: txDetail.vout,
            vin: txDetail.vin,
            opReturnData,
            senderAddress
          };
        } catch {
          return null;
        }
      });

      const mempoolResults = (await Promise.all(mempoolPromises)).filter(Boolean);
      transactions.push(...mempoolResults);
      console.log(`➕ Mempool: ${mempoolResults.length} transactions pertinentes ajoutées`);
    } catch (e) {
      console.warn("⚠️ Mempool non scanné:", e.message);
    }

    console.log(`🎉 Total: ${transactions.length} transactions complètement analysées`);
    return transactions;

  } catch (error) {
    console.error("❌ Erreur récupération transactions:", error);
    return [];
  }
}

  async extractTransactionOpReturn(txid) {
    try {
      const tx = await window.rpc('getrawtransaction', [txid, true]);

      for (const output of tx.vout) {
        if (output.scriptPubKey && output.scriptPubKey.hex) {
          const opReturnData = this.extractOpReturnData(output.scriptPubKey.hex);
          if (opReturnData) return opReturnData;
        }
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  extractOpReturnData(scriptHex) {
    try {
      const script = Buffer.from(scriptHex, "hex");

      if (script.length > 2 && script[0] === 0x6a) {
        let dataStart = 1;
        let dataLength = 0;

        if (script[1] <= 75) {
          dataLength = script[1];
          dataStart = 2;
        } else if (script[1] === 0x4c) {
          dataLength = script[2];
          dataStart = 3;
        } else if (script[1] === 0x4d) {
          dataLength = script[2] + (script[3] << 8);
          dataStart = 4;
        }

        if (script.length >= dataStart + dataLength && dataLength > 0) {
          const data = script.slice(dataStart, dataStart + dataLength).toString("utf8");
          return data;
        }
      }

      return null;
    } catch (error) {
      console.error("❌ Erreur décodage OP_RETURN:", error);
      return null;
    }
  }

  async getTransactionSenderAddress(txid) {
    try {
      const tx = await window.rpc('getrawtransaction', [txid, true]);

      if (tx.vin && tx.vin.length > 0) {
        const firstInput = tx.vin[0];
        if (firstInput.txid && firstInput.vout !== undefined) {
          const prevTx = await window.rpc('getrawtransaction', [firstInput.txid, true]);
          const prevOutput = prevTx.vout[firstInput.vout];

          if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.addresses) {
            return prevOutput.scriptPubKey.addresses[0];
          }
          if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.address) {
            return prevOutput.scriptPubKey.address;
          }
        }
      }

      return "unknown_sender";
    } catch (error) {
      return "unknown_sender";
    }
  }

  getNetworkConfig() {
    return {
      messagePrefix: '\x18Nito Signed Message:\n',
      bech32: 'nito',
      bip32: { public: 0x0488B21E, private: 0x0488ADE4 },
      pubKeyHash: 0x00,
      scriptHash: 0x05,
      wif: 0x80
    };
  }

  splitIntoChunks(data, chunkSize) {
    const chunks = [];
    for (let i = 0; i < data.length; i += chunkSize) {
      chunks.push(data.slice(i, i + chunkSize));
    }
    return chunks;
  }

  generateMessageId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async getAvailableUtxos(address) {
    const scan = await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);
    if (!scan.success || !scan.unspents) return [];

    const viableUtxos = scan.unspents
      .filter(u => u.amount >= 0.000003)
      .map(u => ({
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        scriptPubKey: u.scriptPubKey,
        id: `${u.txid}:${u.vout}`
      }))
      .sort((a, b) => b.amount - a.amount);

    const availableUtxos = viableUtxos.filter(utxo => !this.usedUtxos.has(utxo.id));

    console.log(`📊 UTXOs viables: ${viableUtxos.length}, Disponibles: ${availableUtxos.length}`);
    if (availableUtxos.length > 0) {
      console.log(`💰 Plus gros UTXO disponible: ${availableUtxos[0].amount} NITO`);
    }

    return availableUtxos;
  }
}

const messaging = new NitoMessaging();

function initializeMessagingWhenReady() {
  const checkWalletReady = setInterval(async () => {
    if (window.walletKeyPair && window.walletPublicKey && window.bech32Address) {
      const initialized = await messaging.initialize();
      if (initialized) {
        clearInterval(checkWalletReady);
        setupMessagingInterface();
        console.log('🚀 Interface de messagerie activée avec Noble ECDH');
      }
    }
  }, 1000);
}

function setupMessagingInterface() {
  document.getElementById('publishPubkeyButton')?.addEventListener('click', async () => {
    try {
      showLoadingSpinner(true);
      const result = await messaging.publishPublicKey();
      console.log('✅ Clé publique publiée avec succès !');
    } catch (error) {
      alert(`❌ Erreur: ${error.message}`);
    } finally {
      showLoadingSpinner(false);
    }
  });

  document.getElementById('sendMessageButton')?.addEventListener('click', () => {
    const message = document.getElementById('messageInput')?.value.trim();
    if (!message) {
      alert(i18next.t('errors.enter_message'));
      return;
    }
    if (message.length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH) {
      alert(i18next.t('errors.message_too_long', { length: message.length, max: MESSAGING_CONFIG.MAX_MESSAGE_LENGTH }));
      return;
    }

    document.getElementById('sendMessageForm').style.display = 'block';
  });

  document.getElementById('confirmSendButton')?.addEventListener('click', async () => {
    try {
      showLoadingSpinner(true);
      const message = document.getElementById('messageInput').value.trim();
      const recipient = document.getElementById('recipientAddress').value.trim();

      if (!message || !recipient) {
        alert(i18next.t('errors.fill_all_fields'));
        return;
      }
      if (!recipient.startsWith('nito1')) {
        alert(i18next.t('errors.invalid_bech32'));
        return;
      }

      const result = await messaging.sendMessage(message, recipient);

      if (result.efficient) {
        // Plus d'alert - le showSuccessPopup s'occupe de tout
        console.log(`✅ Message envoyé avec succès ! ID: ${result.messageId}, Transactions: ${result.chunks}/${result.totalChunks}, Coût: ${result.totalCost.toFixed(8)} NITO`);
      } else {
        alert(i18next.t('success_messages.message_sent_partial', {
          messageId: result.messageId,
          chunks: result.chunks,
          totalChunks: result.totalChunks,
          cost: result.totalCost.toFixed(8)
        }));
      }

      document.getElementById('messageInput').value = '';
      document.getElementById('recipientAddress').value = '';
      document.getElementById('sendMessageForm').style.display = 'none';
      updateCharCounter();
    } catch (error) {
      alert(`❌ Erreur: ${error.message}`);
    } finally {
      showLoadingSpinner(false);
    }
  });

  document.getElementById('cancelSendButton')?.addEventListener('click', () => {
    document.getElementById('sendMessageForm').style.display = 'none';
  });

  document.getElementById('clearMessageButton')?.addEventListener('click', () => {
    document.getElementById('messageInput').value = '';
    document.getElementById('sendMessageForm').style.display = 'none';
    updateCharCounter();
  });

  document.getElementById('refreshMessagesButton')?.addEventListener('click', async () => {
    try {
      showLoadingSpinner(true);
      const messages = await messaging.scanInboxMessages();
      displayMessages(messages);
      updateUnreadCounter(messages.filter(m => m.status === 'unread').length);
    } catch (error) {
      alert(`❌ Erreur: ${error.message}`);
    } finally {
      showLoadingSpinner(false);
    }
  });

  document.getElementById('consolidateMessagingButton')?.addEventListener('click', async () => {
    try {
      const confirmed = confirm(i18next.t('encrypted_messaging.consolidate_confirm_message'));

      if (!confirmed) return;

      showLoadingSpinner(true);
      const result = await messaging.consolidateMessagingUtxos();

      if (result.success) {
      alert(i18next.t('errors.consolidation_completed'));
      }
    } catch (error) {
      alert(`❌ Erreur: ${error.message}`);
    } finally {
      showLoadingSpinner(false);
    }
  });

  document.getElementById('messageInput')?.addEventListener('input', updateCharCounter);
  updateCharCounter();
}

function updateCharCounter() {
  const input = document.getElementById('messageInput');
  const counter = document.getElementById('messageCharCounter');
  if (input && counter) {
    const length = input.value.length;
    counter.textContent = i18next.t('messaging_char_counter', { length: length, max: MESSAGING_CONFIG.MAX_MESSAGE_LENGTH });
    counter.className = length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH ? 'char-counter over-limit' : 'char-counter';
  }
}

function displayMessages(messages) {
  const list = document.getElementById('messageList');
  if (!list) return;

  list.innerHTML = '';
  list.style.display = messages.length > 0 ? 'block' : 'none';

  if (messages.length === 0) {
    list.innerHTML = `<div class="message-item">${i18next.t('encrypted_messaging.no_messages')}</div>`;
    return;
  }

  messages.forEach((msg, i) => {
    const div = document.createElement('div');
    div.className = `message-item ${msg.status}`;
    div.dataset.messageId = msg.id;

    const statusIcon = msg.status === 'error' ? '❌' : '📧';
    const statusText = msg.status === 'error' ? i18next.t('encrypted_messaging.message_error') : i18next.t('encrypted_messaging.unread');
    const securityIcon = msg.verified ? '🔐✓' : '🔐';

    div.innerHTML = `
      <div><strong>${statusIcon} ${i18next.t('encrypted_messaging.message')} ${i + 1} ${securityIcon}</strong></div>
      <div><strong>${i18next.t('encrypted_messaging.from')}:</strong> ${msg.sender || msg.senderAddress}</div>
      <div style="white-space: pre-wrap;"><strong>${i18next.t('encrypted_messaging.content')}:</strong> ${msg.content}</div>
      <div class="message-status">
        ${new Date(msg.timestamp).toLocaleString()} - ${statusText}${msg.verified ? ' ✓ ' + i18next.t('encrypted_messaging.signature_verified') : ''}${msg.status !== 'error' ? ' 🔐 ' + i18next.t('encrypted_messaging.noble_ecdh_encryption') : ''}
      </div>
      <div style="margin-top: 10px; padding: 8px; background: #e8f4fd; border-radius: 4px; font-size: 14px; color: #2563eb;">
        💡 <span>${i18next.t('encrypted_messaging.consolidate_to_delete')}</span>
      </div>
    `;

    list.appendChild(div);
  });
}

function updateUnreadCounter(count) {
  const unreadDiv = document.getElementById('unreadMessages');
  const countSpan = document.getElementById('unreadCount');
  if (unreadDiv && countSpan) {
    countSpan.textContent = count;
    unreadDiv.style.display = count > 0 ? 'block' : 'none';
  }
}

function showLoadingSpinner(show) {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) {
    spinner.style.display = show ? 'block' : 'none';
  }

  let progressElement = document.getElementById('messageProgress');
  if (show && !progressElement) {
    progressElement = document.createElement('div');
    progressElement.id = 'messageProgress';
    progressElement.style.position = 'fixed';
    progressElement.style.top = '50%';
    progressElement.style.left = '50%';
    progressElement.style.transform = 'translate(-50%, -50%)';
    progressElement.style.zIndex = '1000';
    progressElement.style.background = 'rgba(255, 255, 255, 0.95)';
    progressElement.style.padding = '20px';
    progressElement.style.borderRadius = '8px';
    progressElement.style.boxShadow = '0 4px 20px rgba(0,0,0,0.3)';
    document.body.appendChild(progressElement);
  } else if (!show && progressElement) {
    document.body.removeChild(progressElement);
  }
}

async function getExplorerUrl(txid) {
  return `https://explorer.nito.network/tx/${txid}`;
}

async function checkTransactionConfirmation(txid) {
  try {
    const tx = await window.rpc('getrawtransaction', [txid, true]);
    return tx.confirmations && tx.confirmations > 0;
  } catch (error) {
    return false;
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeMessagingWhenReady);
} else {
  initializeMessagingWhenReady();
}

console.log('📱 Module de messagerie cryptée NITO avec Noble ECDH + AES-GCM chargé - En attente du wallet...');

window.testFullMessaging = async function() {
  try {
    console.log("🧪 Test complet du système de messagerie Noble ECDH");

    console.log("1. Publication de la clé publique...");
    await messaging.publishPublicKey();

    await new Promise(resolve => setTimeout(resolve, 3000));

    console.log("2. Test d'envoi de message à soi-même...");
    const testMessage = "Message de test crypté Noble ECDH " + Date.now();
    const result = await messaging.sendMessage(testMessage, walletData.bech32Address);

    console.log("✅ Envoi réussi:", result);

    await new Promise(resolve => setTimeout(resolve, 10000));

    console.log("3. Scan des messages reçus...");
    const messages = await messaging.scanInboxMessages();

    console.log("📬 Messages trouvés:", messages.length);
    messages.forEach(msg => {
      console.log(`📧 ${msg.id}: ${msg.content} (${msg.status})`);
    });

  } catch (error) {
    console.error("❌ Test échoué:", error);
  }
};

window.debugMessageAdvanced = async function(messageId) {
  console.log("🔍 DIAGNOSTIC AVANCÉ Noble ECDH:", messageId);

  try {
    const transactions = await messaging.getAddressTransactions(walletData.bech32Address);
    const chunks = [];

    for (const tx of transactions) {
      const opReturnData = await messaging.extractTransactionOpReturn(tx.txid);
      if (opReturnData && opReturnData.includes(messageId)) {
        const messageData = opReturnData.substring(MESSAGING_CONFIG.MESSAGE_PREFIX.length);
        const parts = messageData.split('_');
        if (parts[0] === messageId) {
          chunks.push({
            index: parseInt(parts[1]),
            total: parseInt(parts[2]),
            data: parts.slice(3).join('_'),
            txid: tx.txid
          });
        }
      }
    }

    console.log("📦 Chunks trouvés:", chunks.length);
    chunks.sort((a, b) => a.index - b.index);

    for (let i = 0; i < chunks.length; i++) {
      if (chunks[i].index !== i) {
        console.error(`❌ Chunk manquant à l'index ${i}`);
      }
    }

    const reconstituted = chunks.map(c => c.data).join('');
    console.log("🔗 Message reconstitué, taille:", reconstituted.length);

    try {
      console.log("🔍 Test de déchiffrement Noble ECDH...");
      const result = await messaging.decryptMessage(reconstituted, "test");
      console.log("✅ Déchiffrement Noble ECDH réussi:", result.content);
    } catch (e) {
      console.error("❌ Déchiffrement Noble ECDH échoué:", e.message);
    }

  } catch (error) {
    console.error("❌ Erreur diagnostic:", error);
  }
};

window.testPubkeySearch = async function(address) {
  console.log("🧪 TEST: Recherche manuelle de clé publique pour:", address);

  try {
    const scan = await window.rpc('scantxoutset', ['start', [`addr(${address})`]]);
    console.log("📊 Scan résultat:", scan);

    if (scan.unspents) {
      for (let i = 0; i < Math.min(3, scan.unspents.length); i++) {
        const utxo = scan.unspents[i];
        console.log(`🔍 Analyse UTXO ${i}: ${utxo.txid}`);

        const tx = await window.rpc('getrawtransaction', [utxo.txid, true]);
        console.log("📜 Transaction:", tx);

        for (let j = 0; j < tx.vout.length; j++) {
          const output = tx.vout[j];
          if (output.scriptPubKey && output.scriptPubKey.hex) {
            console.log(`Output ${j} scriptPubKey:`, output.scriptPubKey.hex);

            const script = output.scriptPubKey.hex;
            if (script.startsWith('6a')) {
              console.log("🎯 OP_RETURN détecté!");
              try {
                const dataLength = parseInt(script.substring(2, 4), 16);
                const data = script.substring(4, 4 + (dataLength * 2));
                const decoded = Buffer.from(data, 'hex').toString('utf8');
                console.log("📝 Données décodées:", decoded);

                if (decoded.startsWith('NITOPUB:')) {
                  const pubkey = decoded.substring(8);
                  console.log("🔑 CLÉ PUBLIQUE TROUVÉE:", pubkey);
                  return pubkey;
                }
              } catch (e) {
                console.log("❌ Erreur décodage:", e);
              }
            }
          }
        }
      }
    }

    console.log("❌ Aucune clé publique trouvée");
    return null;
  } catch (error) {
    console.error("❌ Erreur test:", error);
    return null;
  }
};
