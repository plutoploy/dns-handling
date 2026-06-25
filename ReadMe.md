# ACME DNS-01 Domain Management Service

[![Ask Zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIH)](https://deepwiki.com/plutoploy/dns-handling)

This Go-based service manages custom domains and automates certificate issuance via the ACME DNS-01 challenge. It incorporates structured logging, database schema migrations, and exposes a clean REST API alongside a built-in DNS server to respond to challenge verifications.

---

## 🏗️ Architecture & Component Directory

The codebase is organized following modern, decoupled Go layout principles:

- **`cmd/server/`**: Main entrypoint that loads configuration, initializes the database, wires up dependency-injected services, and boots the HTTP and DNS servers.
- **`cmd/getip/`**: CLI utility script that uses `internal/ip` to retrieve the host's public IP and generate a hex-encoded domain.
- **`internal/acme/`**: Handles interactions with the ACME directory (setup account, place orders, complete challenges).
- **`internal/certificates/`**: Manages certificates persistence, expiration, and retrieval.
- **`internal/config/`**: Loads configuration variables from environment or falls back to defaults.
- **`internal/database/`**: Implements migrations, schema bootstrapping, and SQL repositories using libSQL/sqlite.
- **`internal/dns/`**: Contains the built-in DNS server that dynamic challenge resolution relies on, plus TXT record lookup facilities.
- **`internal/domain/`**: Implements domain validation, token creation, and state lifecycle.
- **`internal/http/`**: Contains routing, request/response models, endpoints, and bearer token authorization middleware.
- **`internal/ip/`**: Internal package containing helper libraries for querying public IP addresses and encoding subdomains.
- **`internal/tls/`**: Implements dynamic TLS configuration management using CertMagic.

---

## ⚙️ Configuration & Setup

### 1. Environment Variables

Create a `.env` file in the root directory by copying the example template:

```bash
cp .env.example .env
```

The server loads `.env` automatically on startup, then falls back to the process environment.

Customize the environment variables inside `.env`:

```env
# Database connection string (libSQL/sqlite)
DATABASE_URL=file:./tls.db

# ACME Settings
ACME_EMAIL=your-email@example.com
ACME_DIRECTORY=https://your-acme-directory.example/directory

# Example base URL for curl snippets in this guide
API_BASE_URL=http://your-host:8080

# Server addresses
SERVER_ADDR=:8080
HTTP_ADDR=:80
TLS_ADDR=:443
DNS_ADDR=:53

# Authentication Token (Leave empty to disable authentication)
AUTH_TOKEN=your_secure_bearer_token

# CertMagic storage path
CERTMAGIC_STORAGE_PATH=./certmagic-data

# Logging Level (debug, info, warn, error)
LOG_LEVEL=info
```

### 2. Run Locally

Install the required Go dependencies and run the server:

```bash
go mod tidy
go run cmd/server/main.go
```

To run tests:

```bash
go test ./...
```

---

## 📡 REST API Documentation

If `AUTH_TOKEN` is configured, all API requests must include the authorization header:
`Authorization: Bearer <your_secure_bearer_token>`

### 🛡️ Domain Endpoints

- `POST /domains`: Register a domain (generates a verification token).
- `GET /domains/{id}`: Check verification/issuance status of a domain.
- `POST /domains/{id}/verify`: Validate/verify DNS challenge records.
- `POST /domains/{id}/issue-certificate`: Order ACME DNS-01 certificate.
- `GET /domains/{id}/certificate`: Retrieve certificate metadata.

### 🌐 DNS Endpoints (Built-in Resolver Management)

- `GET /dns/records`: List static and manual DNS records.
- `POST /dns/records`: Add a DNS record. Supports `A`, `AAAA`, `CNAME`, `TXT`, `MX`, and `SRV` records.
- `DELETE /dns/records`: Remove a DNS record.
- `GET /dns/resolve`: Resolves a domain name using the local resolver.

---

## 📖 Operations Manual: Step-by-Step Guide

This guide walks you through registering a custom domain, performing DNS challenge verification, and ordering an ACME certificate using the service endpoints.

### Prerequisites

For this manual, we assume:

- `API_BASE_URL` points to the running server.
- Your configured `AUTH_TOKEN` is `your_secure_bearer_token` (include the header `Authorization: Bearer your_secure_bearer_token` in all API requests).
- You want to register the domain `example.com`.

---

### Step 1: Register the Domain Name

To start the domain lifecycle, submit a registration request. This inserts a record in the database and generates a unique, cryptographically secure `verification_token`.

**Request**:

```bash
curl -X POST "${API_BASE_URL}/domains" \
  -H "Authorization: Bearer your_secure_bearer_token" \
  -H "Content-Type: application/json" \
  -d '{"domain_name": "example.com"}'
```

**Expected Response**:

```json
{
  "id": "e4b9be32-bc56-4b2a-bf3d-4c3111f1816e",
  "domain_name": "example.com",
  "verification_token": "a1b2c3d4e5f6g7h8i9j0",
  "status": "pending",
  "instructions": "Create a TXT record for _acme-challenge.example.com with value: a1b2c3d4e5f6g7h8i9j0"
}
```

_Note the domain `id` returned, which is required for all subsequent steps._

---

### Step 2: Configure the DNS Challenge Record

Before triggering verification, you must publish the challenge token so the verification endpoint can find it. You have two options:

#### Option A: Using Your Public DNS Provider

Log in to your DNS registrar (e.g., Cloudflare, GoDaddy, AWS Route53) and add a TXT record:

- **Type**: `TXT`
- **Name**: `_acme-challenge.example.com`
- **Value**: `a1b2c3d4e5f6g7h8i9j0`
- **TTL**: `300` (or the lowest possible value)

#### Option B: Using the Service's Built-in DNS Server

If you've configured the service's DNS server to be authoritative for your zone, you can inject the record directly via the `/dns/records` endpoint:

```bash
curl -X POST "${API_BASE_URL}/dns/records" \
  -H "Authorization: Bearer your_secure_bearer_token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "_acme-challenge.example.com",
    "type": "TXT",
    "value": "a1b2c3d4e5f6g7h8i9j0",
    "ttl": 300
  }'
```

---

### Step 3: Trigger Domain Verification

Once the TXT record has propagated, command the service to verify the DNS record. It will perform a TXT lookup for `_acme-challenge.example.com` and match the returned values with the token stored in the database.

**Request**:

```bash
curl -X POST "${API_BASE_URL}/domains/e4b9be32-bc56-4b2a-bf3d-4c3111f1816e/verify" \
  -H "Authorization: Bearer your_secure_bearer_token"
```

**Expected Response (Success)**:

```json
{
  "id": "e4b9be32-bc56-4b2a-bf3d-4c3111f1816e",
  "domain_name": "example.com",
  "status": "verified",
  "verified_at": "2026-06-25T16:30:00Z",
  "created_at": "2026-06-25T16:28:00Z"
}
```

_If verification fails, double-check that the TXT record has propagated globally (e.g., using `dig txt _acme-challenge.example.com`)._

---

### Step 4: Issue the Certificate

After the domain is marked as `verified`, start the ACME certificate order process.

**Request**:

```bash
curl -X POST "${API_BASE_URL}/domains/e4b9be32-bc56-4b2a-bf3d-4c3111f1816e/issue-certificate" \
  -H "Authorization: Bearer your_secure_bearer_token"
```

**Expected Response**:

```json
{
  "order_id": "8bb2c970-d86b...",
  "status": "certificate_pending",
  "challenge_domain": "_acme-challenge.example.com",
  "expected_txt_value": "expected_acme_txt_challenge_value",
  "instructions": "Update the TXT record for _acme-challenge.example.com to: expected_acme_txt_challenge_value"
}
```

_The service is now communicating with the ACME CA (e.g. Let's Encrypt) in the background. You must update your TXT record to match the returned `"expected_txt_value"` so the ACME CA can complete the verification challenge._

---

### Step 5: Check Certificate Issuance Status

Wait a few seconds for the background polling loop to resolve the ACME challenge. You can check the current domain status.

**Request**:

```bash
curl "${API_BASE_URL}/domains/e4b9be32-bc56-4b2a-bf3d-4c3111f1816e" \
  -H "Authorization: Bearer your_secure_bearer_token"
```

**Expected Response (Once complete)**:

```json
{
  "id": "e4b9be32-bc56-4b2a-bf3d-4c3111f1816e",
  "domain_name": "example.com",
  "status": "active",
  "created_at": "2026-06-25T16:28:00Z"
}
```

_The status changes to `active` once the certificate is successfully issued and stored in the database._

---

### Step 6: Retrieve the Certificate

After the domain becomes `active`, download the certificate metadata.

**Request**:

```bash
curl "${API_BASE_URL}/domains/e4b9be32-bc56-4b2a-bf3d-4c3111f1816e/certificate" \
  -H "Authorization: Bearer your_secure_bearer_token"
```

**Expected Response**:

```json
{
  "id": "f5c2b329-df56...",
  "domain_id": "e4b9be32-bc56-4b2a-bf3d-4c3111f1816e",
  "issued_at": "2026-06-25T16:35:00Z",
  "expires_at": "2026-09-23T16:35:00Z",
  "created_at": "2026-06-25T16:35:00Z"
}
```

---

### 🛠️ Working with the Dynamic Subdomain Utility

The project includes a CLI tool at `cmd/getip/main.go` to help dynamically generate a hex-encoded domain based on your public IP. To run it:

```bash
go run cmd/getip/main.go -domain=.example.com
```

**Example Output**:

```text
Dynamic Subdomain: c0a80164.example.com
```

This is useful for generating local testing subdomains representing the host's actual IP address.

---

## 🗄️ Database Schema Design

The service maintains state using four core tables:

### 1. `domains`

Stores metadata and status tracking for registered domain names.

- `id`: TEXT PRIMARY KEY (UUID)
- `domain_name`: TEXT NOT NULL UNIQUE
- `verification_token`: TEXT NOT NULL
- `status`: TEXT NOT NULL DEFAULT 'pending' (Values: `pending`, `verified`, `certificate_pending`, `active`, `failed`)
- `verified_at`: TIMESTAMP (Nullable)
- `created_at`: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
- `updated_at`: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP

### 2. `acme_orders`

Tracks certificate orders placed with the ACME provider.

- `id`: TEXT PRIMARY KEY
- `domain_id`: TEXT NOT NULL REFERENCES domains(id)
- `order_url`: TEXT NOT NULL
- `status`: TEXT NOT NULL
- `expires_at`: TIMESTAMP
- `created_at`: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP

### 3. `acme_challenges`

Tracks authorization and challenge statuses required for DNS-01 verification.

- `id`: TEXT PRIMARY KEY
- `domain_id`: TEXT NOT NULL REFERENCES domains(id)
- `authorization_url`: TEXT NOT NULL
- `challenge_url`: TEXT NOT NULL
- `token`: TEXT NOT NULL
- `key_authorization`: TEXT NOT NULL
- `status`: TEXT NOT NULL
- `created_at`: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP

### 4. `certificates`

Stores issued TLS certificates, private keys, and expiration info.

- `id`: TEXT PRIMARY KEY
- `domain_id`: TEXT NOT NULL REFERENCES domains(id)
- `certificate_pem`: TEXT NOT NULL
- `private_key_pem`: TEXT NOT NULL
- `issued_at`: TIMESTAMP NOT NULL
- `expires_at`: TIMESTAMP NOT NULL
- `created_at`: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP

---

## 🔗 Related Resources

- [Mintlify Wiki Documentation](https://mintlify.wiki/plutoploy/dns-handling)
- [Deep Wiki Documentation](https://deepwiki.com/plutoploy/dns-handling)
