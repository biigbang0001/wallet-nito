# Wallet Nito HD + wif/hex Import

Wallet Nito is a comprehensive web-based cryptocurrency wallet for managing NITO tokens. This project allows users to generate private keys, import wallets, send transactions securely, and **exchange encrypted messages on-chain**. It communicates with a NITO node to fetch balances, prepare, and broadcast transactions, while supporting multiple languages for a better user experience.

This README provides step-by-step instructions to set up Wallet Nito on a new machine, including Nginx configuration for secure hosting with HTTPS and support for a generated keys counter.

## Features

- 📬 **Send/receive NITO transactions**
- 🔐 **Secure Key Management**: Generate and import private keys with client-side security
- 🔒 **Encrypted Messaging**: On-chain encrypted messaging system using Noble ECDH + AES-GCM
- 🌍 **Multi-Language Support**: Interface available in 7 languages (FR, EN, DE, ES, NL, RU, ZH)
- 🔄 **UTXO Consolidation**: Cleanup tool for optimizing transaction efficiency
## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- **Ubuntu Server** (or another Linux distribution)
- **Git**
- **Nginx**
- **PHP-FPM** (version 8.1 or compatible, required for the counter)
- A domain name pointed to your server's IP address (`<your-domain>`, e.g., `wallet-nito.nitopool.fr`)
- SSL certificates (e.g., from Let's Encrypt)
- Access to a NITO node (either your own or a public node)

## Installation Steps

### 1. Clone the Repository
Clone the Wallet Nito repository from GitHub to your server:
```bash
git clone https://github.com/biigbang0001/wallet-nito.git /var/www/wallet-nito
cd /var/www/wallet-nito
```

### 2. Set Up a NITO Node (Recommended)
For better efficiency and decentralization, we strongly recommend setting up your own NITO node instead of relying on a single node.

**Option 1: Set Up Your Own NITO Node**  
Follow the official NITO documentation to set up a NITO node on your server or another machine. This typically involves:
- Downloading the NITO node software. 
```bash
https://nito.network/tools/easynode/
```
- Configuring the node (e.g., setting up `nito.conf` with appropriate settings).
- Starting the node and ensuring it syncs with the NITO network.  
Note the IP address and port of your NITO node (e.g., `http://<your-node-ip>:<port>`). If your node requires authentication, note the username and password (you'll need to encode them in Base64 for the Nginx configuration).

**Option 2: Use a Public NITO Node**  
If setting up your own node is not feasible, you can use a public NITO node, such as `http://217.160.149.211:8825/`. Be aware of potential privacy and reliability issues with third-party nodes. Note the URL and authentication details if required (e.g., `user:pass` encoded in Base64: `dXNlcjpwYXNz`).

### 3. Set Up File Permissions
Ensure that the web server user (e.g., `www-data` for Nginx) has the appropriate permissions to access the project files:
```bash
sudo chown -R www-data:www-data /var/www/wallet-nito
sudo chmod -R 755 /var/www/wallet-nito
```

### 4. Configure the Generated Keys Counter
The project includes a counter to track the number of NITO keys generated. This requires creating a file to store the counter and a PHP script to manage it.

**4.1 Create the Counter File**  
Create a file `counter.txt` to store the number of generated keys:
```bash
sudo mkdir -p /var/www/wallet-nito/data
echo "0" | sudo tee /var/www/wallet-nito/data/counter.txt
sudo chown www-data:www-data /var/www/wallet-nito/data/counter.txt
sudo chmod 600 /var/www/wallet-nito/data/counter.txt
```

**4.2 Create the PHP Script to Manage the Counter**  
Create a PHP script to read and increment the counter:
```bash
sudo mkdir -p /var/www/wallet-nito/api/
sudo nano /var/www/wallet-nito/api/counter.php
```
Add the following content to `counter.php`:
```php
<?php
header('Content-Type: application/json');

// Path to the counter file
$counterFile = '/var/www/wallet-nito/data/counter.txt';

// Function to read the counter
function readCounter($file) {
    if (!file_exists($file)) {
        return 0;
    }
    return (int)file_get_contents($file);
}

// Function to increment the counter
function incrementCounter($file) {
    $count = readCounter($file);
    $count++;
    file_put_contents($file, $count, LOCK_EX);
    return $count;
}

// Handle requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Endpoint /api/get-counter
    $count = readCounter($counterFile);
    echo json_encode(['count' => $count]);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Endpoint /api/increment-counter
    $count = incrementCounter($counterFile);
    echo json_encode(['count' => $count]);
} else {
    http_response_code(405);
    echo json_encode(['error' => 'Method Not Allowed']);
}
?>
```
Set the appropriate permissions:
```bash
sudo chown www-data:www-data /var/www/wallet-nito/api/counter.php
sudo chmod 644 /var/www/wallet-nito/api/counter.php
```

### 5. Install PHP (if Needed)
The `counter.php` script requires PHP-FPM. Check if PHP is installed:
```bash
php -v
```
If PHP is not installed, install it (e.g., PHP 8.1):
```bash
sudo apt update
sudo apt install php-fpm
```
Verify the PHP-FPM socket used:
```bash
ls /run/php/
```
Note the socket name (e.g., `php8.1-fpm.sock`). You'll need this for the Nginx configuration.

### 6. Configure Nginx
Set up Nginx to serve the Wallet Nito application securely over HTTPS, proxy API requests to your NITO node, and handle counter endpoints.

**6.1 Obtain SSL Certificates**  
If you don't already have SSL certificates, use Let's Encrypt to obtain them for your domain:
```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d <your-domain>
```
Replace `<your-domain>` with your domain (e.g., `wallet-nito.nitopool.fr`).

**6.2 Create an Nginx Configuration File**  
Create or edit the Nginx configuration file for your domain:
```bash
sudo nano /etc/nginx/sites-available/<your-domain>
```
Add the following configuration, replacing `<your-domain>` with your domain (e.g., `wallet-nito.nitopool.fr`) and `<your-node-url>` with the URL of your NITO node (e.g., `http://217.160.149.211:8825/`). If your node requires authentication, replace `<base64-auth>` with the Base64-encoded `username:password` (e.g., `dXNlcjpwYXNz` for `user:pass`).

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name <your-domain>;

    # Redirect all HTTP requests to HTTPS
    return 301 https://$host$request_uri;
}

# HTTPS configuration with proxy to the node
server {
    listen 443 ssl;
    server_name <your-domain>;

    # Path to Let's Encrypt certificates
    ssl_certificate /etc/letsencrypt/live/<your-domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<your-domain>/privkey.pem;

    # Enhance SSL security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;

    # HSTS to enforce HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Root directory for static files
    root /var/www/wallet-nito;
    index index.html;

    # Content Security Policy (CSP)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://esm.sh https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; connect-src 'self' https://<your-domain>/api/ https://<your-domain>/langs/ https://explorer.nito.network https://explorer.nito.network/ext/gettx/ https://nitoexplorer.org https://nitoexplorer.org/ext/gettx/ https://esm.sh https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' https://raw.githubusercontent.com; style-src 'self' 'unsafe-inline';";

    # Proxy for API requests to your NITO node (via /api/) without cache
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
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization,Content-Type' always;
            add_header 'Content-Length' 0;
            return 204;
        }
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Routes for counter endpoints without cache
    location /api/increment-counter {
        try_files $uri $uri/ /api/counter.php;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    location /api/get-counter {
        try_files $uri $uri/ /api/counter.php;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    # Serve translation files with CORS (via /langs/) without cache
    location /langs/ {
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
            add_header 'Content-Length' 0;
            return 204;
        }
        try_files $uri $uri/ =404;
    }

    # Handle JS/CSS/HTML files without cache (except index.html served via /index.html)
    location ~* \.(js|css|html)$ {
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        try_files $uri $uri/ =404;
    }

    # Handle JSON files without cache (except those in /langs/ managed by /langs/)
    location ~* \.json$ {
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        add_header Content-Type "application/json";
        try_files $uri $uri/ =404;
    }

    # Handle PHP scripts without cache
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock; # Adjust based on your PHP version (e.g., php8.1-fpm.sock)
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    # Serve only index.html with cache
    location = /index.html {
        expires 30d;
        add_header Cache-Control "public, max-age=2592000";
    }

    # Root location to handle uncatched requests (redirect to index.html if needed)
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

**6.3 Enable the Nginx Configuration**  
Create a symbolic link to enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/<your-domain> /etc/nginx/sites-enabled/
```

**6.4 Test and Restart Nginx**  
Test the Nginx configuration for syntax errors, then restart Nginx to apply the changes:
```bash
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl restart php8.1-fpm # Restart PHP-FPM to ensure it's ready
```

### 7. Access the Wallet
Open your browser and navigate to `https://<your-domain>`. You should see the Wallet Nito interface, where you can generate private keys, import wallets, send NITO transactions, and exchange encrypted messages. The generated keys counter is displayed below the "Wallet NITO" title (e.g., "🔑 Nito Keys Generated: X").

## Encrypted Messaging System

Wallet Nito includes an advanced **on-chain encrypted messaging system** with the following features:

### 🔐 **Cryptographic Security**
- **ECDH Key Exchange**: Uses Noble secp256k1 for secure key derivation
- **AES-GCM Encryption**: Industry-standard symmetric encryption
- **Message Signing**: Cryptographic signatures for authenticity verification
- **Public Key Publishing**: On-chain public key distribution system

### 📨 **Messaging Features**
- **Encrypted Messages**: Send private messages stored on the NITO blockchain
- **Message Chunking**: Automatic splitting of large messages into blockchain-compatible chunks
- **Message Reconstruction**: Automatic reassembly of chunked messages
- **Progress Tracking**: Real-time progress indicators for message operations
- **Message History**: View and manage received encrypted messages

### 🔧 **Technical Implementation**
- **OP_RETURN Storage**: Messages stored in Bitcoin-compatible OP_RETURN outputs
- **UTXO Management**: Smart filtering to preserve messaging data during transactions
- **Chunk Validation**: Automatic verification of message integrity
- **Error Handling**: Robust error recovery for incomplete or corrupted messages

### 🛠 **Smart UTXO Management**
The wallet implements intelligent UTXO filtering to ensure messaging functionality:

- **Automatic Filtering**: Normal transactions automatically avoid UTXOs containing messaging data
- **Consolidation Control**: Manual consolidation allows cleaning of old messages
- **Change Protection**: Transaction change outputs are correctly identified as spendable
- **Data Preservation**: Messaging keys and active conversations are protected from accidental spending

## Security Features

### 🔒 **Client-Side Security**
- **Private Key Protection**: Keys are blurred and auto-expire after inactivity
- **Memory Management**: Sensitive data is cleared after timeout periods
- **Local Processing**: Key generation and signing performed entirely client-side

### 🛡️ **Network Security**
- **HTTPS Enforcement**: All communications encrypted with TLS
- **Content Security Policy**: XSS protection through strict CSP headers
- **CORS Configuration**: Secure cross-origin resource sharing
- **Authentication**: Secure node authentication with Base64 encoding

### ⚠️ **Important Security Notes**

- **HTTPS**: The Nginx configuration enforces HTTPS with a redirect from HTTP and uses modern TLS protocols for security.
- **Content Security Policy (CSP)**: The CSP header restricts the sources from which scripts, connections, and images can be loaded, reducing the risk of cross-site scripting (XSS) attacks.
- **CORS**: CORS headers are configured for `/api/` and `/langs/` to allow the frontend to communicate with the NITO node and load translation files.
- **Offline Operations**: Key generation and wallet importation are performed client-side (in the browser) and do not require a network connection. However, fetching balances, preparing transactions, and broadcasting transactions require connectivity to a NITO node.
- **Secure Counter**: The `counter.txt` file is protected with strict permissions (read/write only for `www-data`), and no sensitive data is stored.
- **Message Privacy**: Encrypted messages are stored on-chain but can only be decrypted by the intended recipient.

## Troubleshooting

### Common Issues

**Nginx Errors**: If Nginx fails to start, check the error logs:
```bash
sudo tail -f /var/log/nginx/error.log
```

**CORS Issues**: Ensure the CORS headers in the Nginx configuration match your frontend requirements.

**SSL Certificate Issues**: If the SSL certificates are not found, re-run the Certbot command to obtain new certificates.

**Node Connectivity**: If the wallet cannot connect to your NITO node, verify that the node at `<your-node-url>` is accessible and that the HTTP Basic Authentication credentials (if used) are correct.

**Translation Loading Errors**: If you encounter JSON parsing errors for translation files, verify that all translation files in `/langs/` are valid JSON format.

**UTXO Management Issues**: If transactions fail after messaging operations:
1. Try consolidating UTXOs using the "Consolidate UTXOs" button
2. After consolidation, republish your public key for messaging
3. Verify the `filterOpReturnUtxos` function is correctly implemented

### Messaging System Troubleshooting

**Message Sending Failures**: 
- Ensure recipient has published their public key
- Check that you have sufficient UTXOs without OP_RETURN data
- Try consolidating UTXOs if needed

**Message Receiving Issues**:
- Verify your public key is published on-chain
- Check that message scanning is completing successfully
- Ensure your node is fully synchronized

**Encryption Errors**:
- Verify both sender and recipient have valid public keys
- Check that Noble ECDH library is loading correctly
- Confirm AES-GCM encryption is supported by the browser

## Contributing

Feel free to fork this repository, make improvements, and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines

- Follow existing code style and conventions
- Test messaging functionality thoroughly
- Ensure security best practices are maintained
- Update documentation for new features
- Verify multilingual support for new UI elements

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

---

**Wallet Nito** - Secure, feature-rich NITO wallet with encrypted messaging capabilities.
