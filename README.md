# Wallet Nito — HD + WIF/HEX Import

**Wallet Nito** is a web-based cryptocurrency wallet for managing **NITO**. It lets you generate/import keys, send transactions securely, and **exchange encrypted messages on-chain**. The frontend talks to a NITO node for UTXOs, fee hints, transaction prep/broadcast, and ships with multilingual UI.

This guide includes a **fast setup**, a **production Nginx** configuration (HTTPS + reverse proxy), and the **generated keys counter (REQUIRED)**.

## Features

* 📬 Send / receive NITO
* 🔐 Key Management — Client-side HD key generator; import by HD and WIF/HEX keys 
* 🔒 Encrypted Messaging — Noble ECDH + **AES-GCM**, stored via **OP\_RETURN**
* 🌍 Multi-Language — FR, EN, DE, ES, NL, RU, ZH
* 🔄 UTXO Consolidation — one-click cleanup tool
* 🧭 HD Support — BIP84 Bech32 + BIP86 Taproot; descriptor-based scanning

---

## Quick Start (5 minutes)

1. **Clone**:

   ```bash
   git clone https://github.com/biigbang0001/wallet-nito.git /var/www/wallet-nito
   cd /var/www/wallet-nito
   sudo chown -R www-data:www-data .
   sudo chmod -R 755 .
   ```
2. **Enable the keys counter** (PHP endpoint + writable file). See **Generated Keys Counter ** below.
3. **Reverse proxy `/api/`** to your NITO node with **Nginx** (sample config below).
4. Visit `https://<your-domain>`:

   * Generate or import a key (WIF/HEX unchanged).
   * See balance/UTXOs, **send NITO**, try **encrypted messaging**.

> The reverse proxy avoids CORS issues and keeps your node URL/auth server-side.

---

## Requirements

* Linux server (Ubuntu recommended), domain with DNS set up
* **Nginx** (reverse proxy + TLS), **Git**
* **PHP-FPM (REQUIRED)** — used by the **generated keys counter**
* A reachable **NITO node** (yours or a trusted one)

---

## Node Options

**Option A — Your own NITO node (recommended):**

* Install & sync a node; note `http(s)://<node>:<port>` and (if set) `user:pass` (Base64 for proxy auth).

**Option B — Public node:**

* Possible for testing; mind privacy/reliability. Use your own node for production.

---

## Nginx (HTTPS + Reverse Proxy)

Issue TLS certs:

```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d <your-domain>
```

Sample site config (`/etc/nginx/sites-available/<your-domain>`). Replace placeholders:

* `<your-domain>` e.g. `wallet-nito.example.com`
* `<your-node-url>` e.g. `http://127.0.0.1:8825/`
* `<base64-auth>` if your node uses HTTP Basic auth (Base64 of `user:pass`)
* Adjust the PHP-FPM socket path to your version (e.g. `php8.1-fpm.sock`)

```nginx
server {
    listen 80;
    server_name <your-domain>;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name <your-domain>;

    ssl_certificate /etc/letsencrypt/live/<your-domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<your-domain>/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/wallet-nito;
    index index.html;

    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://esm.sh https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; connect-src 'self' https://<your-domain>/api/ https://<your-domain>/langs/ https://explorer.nito.network https://nitoexplorer.org https://esm.sh https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' https://raw.githubusercontent.com; style-src 'self' 'unsafe-inline';" always;

    # Proxy to your node (no-cache + CORS for the webapp)
    location /api/ {
        proxy_pass <your-node-url>;
        proxy_set_header Authorization "Basic <base64-auth>";
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Authorization,Content-Type' always;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        if ($request_method = 'OPTIONS') {
            add_header 'Content-Length' 0; return 204;
        }
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Translations with CORS, no-cache
    location /langs/ {
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        if ($request_method = 'OPTIONS') {
            add_header 'Content-Length' 0; return 204;
        }
        try_files $uri $uri/ =404;
    }

    # No-cache for static assets except index.html
    location ~* \.(js|css|html|json)$ {
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        try_files $uri $uri/ =404;
    }

    # REQUIRED: PHP for the generated keys counter
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;  # adjust to your PHP version
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    # Cache index.html lightly (optional)
    location = /index.html {
        expires 30d;
        add_header Cache-Control "public, max-age=2592000";
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/<your-domain> /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

---

## Generated Keys Counter 

The frontend expects a working counter endpoint and a writable counter file.

1. Create storage & set permissions:

```bash
sudo mkdir -p /var/www/wallet-nito/data /var/www/wallet-nito/api
echo "0" | sudo tee /var/www/wallet-nito/data/counter.txt
sudo chown -R www-data:www-data /var/www/wallet-nito/data
sudo chmod 600 /var/www/wallet-nito/data/counter.txt
```

2. Create the PHP endpoint at **`/var/www/wallet-nito/api/counter.php`**:

```php
<?php
header('Content-Type: application/json');
$counterFile = '/var/www/wallet-nito/data/counter.txt';
function readCounter($f){ return file_exists($f) ? (int)file_get_contents($f) : 0; }
function incrementCounter($f){ $c=readCounter($f)+1; file_put_contents($f,$c,LOCK_EX); return $c; }
if($_SERVER['REQUEST_METHOD']==='GET'){ echo json_encode(['count'=>readCounter($counterFile)]); }
elseif($_SERVER['REQUEST_METHOD']==='POST'){ echo json_encode(['count'=>incrementCounter($counterFile)]); }
else{ http_response_code(405); echo json_encode(['error'=>'Method Not Allowed']); }
```

3. Make sure your Nginx PHP location block is active (see above), and that `/api/counter.php` is reachable:

```bash
curl -s https://<your-domain>/api/counter.php
# -> {"count":0}
```

> The app will invoke this endpoint on load and when generating a new key. If it returns 404/500 or cannot write to `counter.txt`, you’ll see errors in the UI.

---

## Address Types & HD Support

* **Bech32 (BIP84)** — **P2WPKH** (used by the messaging system)
* **Bech32m (BIP86)** — **P2TR** (Taproot)
* 
### HD Scan & Recovery

* **Descriptors**:

  * BIP84: `wpkh(xpub/0/*)` + `wpkh(xpub/1/*)`
  * BIP86: `tr(xpub/0/*)` + `tr(xpub/1/*)`
* **Smart range growth**: start at **512**, **double** while near boundary, up to **50,000 per branch** (0=receive, 1=change).
* **Spend-only derivation**: only required private keys are derived at signing time based on descriptor **(branch/index)**.
* **No missed change**: deep change chains are discovered (useful after many sends).

---

## Fee Policy

* `effectiveFeeRate = max( estimatesmartfee(6), mempoolminfee, relayfee, min_fee )`
* `fees = ceil( vbytes × effectiveFeeRate × 1.2 × 1e8 / 1000 )`

Details:

* If the node can’t produce a feerate (e.g., *“Insufficient data or no feerate found”*), the wallet falls back to `mempoolminfee` / `relayfee`.
* **vbytes** estimation accounts for:

  * **Input type**: P2WPKH vs P2TR
  * **Outputs**: destination **+ change** when applicable (or destination only for **sweep/MAX**)

---

## UTXO Policy

* **Protection for normal transactions**: **all UTXOs > 0.00005 NITO are excluded** from selection (they often carry messaging dust/metadata or are too small to spend efficiently).
* **Consolidation**: ignores the protection and **spends absolutely everything** to a single output (your address) to tidy your UTXO set.
* **MAX button**: uses **all spendable UTXOs** (after the protection rule) and **deducts fees** before auto-filling the amount.

> Messaging uses **Bech32 (P2WPKH)**. Protection applies to small UTXOs regardless of origin.

---

## Encrypted Messaging (How-To)

1. **Publish your messaging public key** (UI action).
2. **Enter recipient’s NITO address** (they must have published a key).
3. **Write & send** — the message is ECDH-derived, encrypted with AES-GCM, then committed via **OP\_RETURN**.
4. If you’ve sent many messages and normal spends struggle, **run consolidation** and re-publish if needed.

Under the hood:

* Key exchange: Noble secp256k1 **ECDH**
* Encryption: **AES-GCM**
* Storage: **OP\_RETURN** chunks (+ reassembly)

---

## Security

* **Client-side** keygen/import/signing; sensitive values blurred and cleared after inactivity
* **HTTPS** enforced by Nginx; strict **CSP**; **CORS** restricted to `/api/` and `/langs/`
* Node credentials (if any) stay server-side via reverse proxy
* Counter data has strict file permissions; no secrets stored

---

## Troubleshooting

**“min relay fee not met”**

* Node mempool requires a higher feerate than your calc. Try later, consolidate, or confirm node’s `mempoolminfee/relayfee`.

**“Insufficient data or no feerate found” (estimatesmartfee)**

* The wallet automatically falls back to `mempoolminfee/relayfee`. Ensure your node is synced and has peers.

**Counter errors**

* `GET /api/counter.php` must return JSON and be writable. Check:

  * PHP-FPM running and Nginx `location ~ \.php$` block
  * File exists: `/var/www/wallet-nito/data/counter.txt`
  * Ownership/permissions: `www-data` + `600`
  * HTTPS returns: `{"count": <number>}`

**CORS / TLS**

* Confirm Nginx headers and that your domain is covered by valid certificates.

**Translations**

* If a locale fails to load, confirm your `/langs/*.json` are valid JSON.

---

## Contributing

* Follow the current code style and naming (unchanged terms/labels for smooth integration)
* Test both **Bech32** and **Taproot** paths (send, MAX, consolidation)
* Keep security and multilingual UI in mind
* Update this README for any new features

## License

GPLv3 — see `LICENSE`.

---

**Wallet Nito** — Secure NITO wallet with HD support and on-chain encrypted messaging.
