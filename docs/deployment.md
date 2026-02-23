# Production Deployment

This guide covers deploying Chalk in a production environment with a reverse proxy, process management, and basic network security.

## Overview

A typical production setup looks like:

```
Internet -> Reverse Proxy (443/HTTPS) -> Chalk (localhost:8080)
```

Chalk runs as a single binary listening on a local port. A reverse proxy (Caddy or nginx) handles TLS termination and forwards traffic to Chalk.

## Caddy Reverse Proxy

[Caddy](https://caddyserver.com/) is the recommended reverse proxy for Chalk because it automatically provisions and renews TLS certificates via Let's Encrypt.

Create a `Caddyfile`:

```caddyfile
chalk.example.com {
    reverse_proxy localhost:8080

    # Optional: restrict access to internal networks
    # @blocked not remote_ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    # abort @blocked
}
```

Start Caddy:

```bash
sudo caddy start --config /etc/caddy/Caddyfile
```

Caddy will automatically obtain a TLS certificate for `chalk.example.com` and redirect HTTP to HTTPS.

## nginx Alternative

If you prefer nginx, create a site configuration:

```nginx
server {
    listen 80;
    server_name chalk.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chalk.example.com;

    ssl_certificate     /etc/letsencrypt/live/chalk.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chalk.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/chalk /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

You can use [Certbot](https://certbot.eff.org/) to obtain and auto-renew certificates with nginx.

## systemd Service

Create a systemd unit file at `/etc/systemd/system/chalk.service`:

```ini
[Unit]
Description=Chalk K-12 Data Platform
After=network.target

[Service]
Type=simple
User=chalk
Group=chalk
ExecStart=/usr/local/bin/chalk serve --config /var/lib/chalk/chalk.toml --port 8080
WorkingDirectory=/var/lib/chalk
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/chalk

[Install]
WantedBy=multi-user.target
```

Set up the service:

```bash
# Create a dedicated user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin chalk
sudo chown -R chalk:chalk /var/lib/chalk

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable chalk
sudo systemctl start chalk

# Check status
sudo systemctl status chalk
sudo journalctl -u chalk -f
```

## Firewall Notes

Chalk itself only needs to listen on localhost. The reverse proxy handles external traffic.

**Ports to open:**

| Port | Protocol | Purpose |
|------|----------|---------|
| 443  | TCP      | HTTPS (reverse proxy) |
| 80   | TCP      | HTTP redirect to HTTPS (optional) |

**Ports that should remain closed to the public:**

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | TCP      | Chalk's local listener (reverse proxy only) |

If you use `ufw`:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp    # optional, for HTTP-to-HTTPS redirect
sudo ufw enable
```

If you use `firewalld`:

```bash
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=http   # optional
sudo firewall-cmd --reload
```

## Verifying the Deployment

After starting Chalk and the reverse proxy:

```bash
# Check Chalk is running
sudo systemctl status chalk

# Check the health endpoint through the proxy
curl -s https://chalk.example.com/health

# Check TLS certificate
curl -vI https://chalk.example.com 2>&1 | grep "SSL certificate"
```

## Next Steps

- Review the [Security](security.md) guide for hardening recommendations
- Set up [Google Workspace Sync](google-sync.md) or [Active Directory Sync](ad-sync.md) for automated provisioning
- Configure [Webhooks](webhooks.md) for real-time event notifications
