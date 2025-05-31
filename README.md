Wallet Nito
Wallet Nito is a web-based cryptocurrency wallet for managing NITO tokens. This project allows users to generate private keys, import wallets, and send transactions securely. It communicates with a NITO node to fetch balances, prepare, and broadcast transactions, while supporting multiple languages for a better user experience.
This README provides step-by-step instructions to set up Wallet Nito on a new machine, including Nginx configuration for secure hosting with HTTPS.
Prerequisites
Before you begin, ensure you have the following installed on your machine:

Ubuntu Server (or another Linux distribution)
Git
Nginx
Node.js and npm (for managing dependencies)
A domain name pointed to your server's IP address (<your-domain>)
SSL certificates (e.g., from Let's Encrypt)
Access to a NITO node (either your own or a public node)

Installation Steps
1. Clone the Repository
Clone the Wallet Nito repository from GitHub to your server:
git clone https://github.com/biigbang0001/wallet-nito.git /var/www/wallet-nito
cd /var/www/wallet-nito

2. Install Dependencies
The project includes a package.json file with dependencies. Install them using npm:
npm install

This will create a node_modules directory with the required dependencies. Note that node_modules is excluded from the repository via .gitignore, so it will be generated locally.
3. Set Up a NITO Node (Recommended)
For better efficiency and decentralization, we strongly recommend setting up your own NITO node instead of relying on a single node. Using a centralized node (such as http://217.160.149.211:8825/) can lead to performance bottlenecks and reduces the decentralized nature of the network.
Option 1: Set Up Your Own NITO Node

Follow the official NITO documentation to set up a NITO node on your server or another machine. This typically involves:
Downloading the NITO node software.
Configuring the node (e.g., setting up nito.conf with appropriate settings).
Starting the node and ensuring it syncs with the NITO network.


Note the IP address and port of your NITO node (e.g., http://<your-node-ip>:<port>).
If your node requires authentication, note the username and password (you’ll need to encode them in Base64 for the Nginx configuration).

Option 2: Use a Public NITO Node
If setting up your own node is not feasible, you can use a public NITO node. However, be aware of potential privacy and reliability issues with third-party nodes. Search for a trusted public NITO node and note its URL and authentication details (if required).
4. Set Up File Permissions
Ensure that the web server user (e.g., www-data for Nginx) has the appropriate permissions to access the project files:
chown -R www-data:www-data /var/www/wallet-nito
chmod -R 755 /var/www/wallet-nito

5. Configure Nginx
You need to set up Nginx to serve the Wallet Nito application securely over HTTPS and proxy API requests to your NITO node.
5.1 Obtain SSL Certificates
If you don’t already have SSL certificates, use Let's Encrypt to obtain them for your domain:
sudo apt update
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d <your-domain>

Follow the prompts to obtain and install the certificates. They will typically be stored in /etc/letsencrypt/live/<your-domain>/.
5.2 Create an Nginx Configuration File
Create a new Nginx configuration file for your domain:
sudo nano /etc/nginx/sites-available/<your-domain>

Paste the following configuration, replacing <your-domain> with your actual domain name and <your-node-url> with the URL of your NITO node (e.g., http://<your-node-ip>:<port>/). If your node requires authentication, replace <base64-auth> with the Base64-encoded username:password (e.g., for user:pass, the Base64 value is dXNlcjpwYXNz).
# Redirection HTTP vers HTTPS
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

    # Root directory for static files
    root /var/www/wallet-nito;
    index index.html;

    # Content Security Policy (CSP) configuration
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://esm.sh https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; connect-src 'self' https://<your-domain>/api/ https://<your-domain>/langs/ https://explorer.nito.network https://explorer.nito.network/ext/gettx/ https://nitoexplorer.org https://nitoexplorer.org/ext/gettx/; img-src 'self' https://raw.githubusercontent.com; style-src 'self' 'unsafe-inline';";

    # Proxy for API requests to your NITO node (via /api/)
    location /api/ {
        # URL of your NITO node
        proxy_pass <your-node-url>;

        # Inject HTTP Basic Authentication (if required by your node)
        # Replace <base64-auth> with the Base64-encoded "username:password"
        # Example: For "user:pass", use "dXNlcjpwYXNz"
        proxy_set_header Authorization "Basic <base64-auth>";

        # Add CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Authorization,Content-Type' always;

        # Handle OPTIONS requests (CORS preflight)
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization,Content-Type' always;
            add_header 'Content-Length' 0;
            return 204;
        }

        # Additional proxy settings
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Serve translation files with CORS (via /langs/)
    location /langs/ {
        # Add CORS headers for JSON files
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type' always;

        # Handle OPTIONS requests (CORS preflight)
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
            add_header 'Content-Length' 0;
            return 204;
        }

        # Serve static files
        try_files $uri $uri/ =404;
    }

    # Serve other static files (index.html, wallet.js, etc.)
    location / {
        try_files $uri $uri/ /index.html;
    }
}

5.3 Enable the Nginx Configuration
Create a symbolic link to enable the site:
sudo ln -s /etc/nginx/sites-available/<your-domain> /etc/nginx/sites-enabled/

5.4 Test and Restart Nginx
Test the Nginx configuration for syntax errors, then restart Nginx to apply the changes:
sudo nginx -t
sudo systemctl restart nginx

If nginx -t reports any errors, review the configuration file for typos or missing files (e.g., SSL certificates).
6. Access the Wallet
Open your browser and navigate to https://<your-domain>. You should see the Wallet Nito interface, where you can generate private keys, import wallets, and send NITO transactions.
Security Notes

HTTPS: The Nginx configuration enforces HTTPS with a redirect from HTTP and uses modern TLS protocols for security.
Content Security Policy (CSP): The CSP header restricts the sources from which scripts, connections, and images can be loaded, reducing the risk of cross-site scripting (XSS) attacks.
CORS: CORS headers are configured for /api/ and /langs/ to allow the frontend to communicate with the NITO node and load translation files.
Offline Operations: Key generation and wallet importation are performed client-side (in the browser) and do not require a network connection. However, fetching balances, preparing transactions, and broadcasting transactions require connectivity to a NITO node.

Troubleshooting

Nginx Errors: If Nginx fails to start, check the error logs:sudo tail -f /var/log/nginx/error.log


CORS Issues: Ensure the CORS headers in the Nginx configuration match your frontend requirements.
SSL Certificate Issues: If the SSL certificates are not found, re-run the Certbot command to obtain new certificates.
Node Connectivity: If the wallet cannot connect to your NITO node, verify that the node at <your-node-url> is accessible and that the HTTP Basic Authentication credentials (if used) are correct.

Contributing
Feel free to fork this repository, make improvements, and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.
License
This project is licensed under the MIT License. See the LICENSE file for details.
