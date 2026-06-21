# ACME DNS-01 Domain Management Service

This is a Go service that manages custom domains and handles ACME DNS-01 certificate issuance. It uses libSQL (tursodb) for the database and `chi` for the HTTP framework.

## 1. Setup & Configuration

First, set up your environment variables by copying the example `.env` file:

```bash
cp .env.example .env
```

Inside the `.env` file, configure your database, Let's Encrypt endpoint (currently set to staging), and server address:

```env
# Database (uses libSQL/turso locally)
DATABASE_URL=file:./tls.db

# ACME
ACME_EMAIL=admin@example.com
ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory

# Server
SERVER_ADDR=:8080

# Logging
LOG_LEVEL=info
```

## 2. Run the Server

Ensure you have your dependencies installed and run the main server:

```bash
go mod tidy
go run cmd/server/main.go
```

## 3. Using the REST API

Once the server is running on `localhost:8080`, you can interact with the domain lifecycle via the provided REST endpoints:

### Step 1: Register a Domain
Submit a domain name to generate a verification token.

```bash
curl -X POST http://localhost:8080/domains \
  -H "Content-Type: application/json" \
  -d '{"domain_name": "example.com"}'
```
*The response will give you a domain `id` and a `verification_token` to set as a `_acme-challenge` TXT record in your DNS.*

### Step 2: Check Domain Status
Check the status of your domain using the ID returned in the previous step.

```bash
curl http://localhost:8080/domains/<domain_id>
```

### Step 3: Trigger Verification
Once you've added the TXT record to your DNS, tell the server to verify it.

```bash
curl -X POST http://localhost:8080/domains/<domain_id>/verify
```

### Step 4: Issue Certificate
After verification succeeds, start the ACME DNS-01 certificate order.

```bash
curl -X POST http://localhost:8080/domains/<domain_id>/issue-certificate
```

### Step 5: Retrieve Certificate
Finally, once the certificate is generated, you can retrieve its metadata.

```bash
curl http://localhost:8080/domains/<domain_id>/certificate
```
