Build a production-ready Go service that manages custom domains and ACME DNS-01 certificate issuance.

Requirements:

Language: Go 

Database: libSQL (tursodb)

HTTP framework:  Go (chi)

DNS lookup: net.Resolver

Configuration via environment variables

Structured logging

Domain lifecycle:

User submits a domain name.

Generate a cryptographically secure verification token.

Store domain record in db.

Return instructions to create:

\_acme-challenge. TXT

Expose an API endpoint to trigger verification.

Verification must query public DNS and confirm the TXT record matches the stored token.

Mark the domain as verified in db.

After verification, start an ACME DNS-01 certificate order.

Persist ACME authorization, challenge, order, and certificate metadata.

Store issued certificate and private key.

Support certificate renewal.

Database schema:

domains

id (uuid)

domain_name

verification_token

status (pending, verified, certificate_pending, active, failed)

verified_at

created_at

updated_at

acme_orders

id (uuid)

domain_id

order_url

status

expires_at

created_at

acme_challenges

id (uuid)

domain_id

authorization_url

challenge_url

token

key_authorization

status

created_at

certificates

id (uuid)

domain_id

certificate_pem

private_key_pem

issued_at

expires_at

created_at

REST API:

POST /domains

Create domain

Generate verification token

GET /domains/

Return domain status

POST /domains//verify

Verify TXT record

POST /domains//issue-certificate

Start ACME order

GET /domains//certificate

Return certificate metadata

Implementation requirements:

Organize code into:

cmd/server

internal/acme

internal/domain

internal/database

internal/http

internal/dns

internal/certificates

Use dependency injection.

Add interfaces for DNS resolver, ACME provider, and repositories.

Include migrations.

Include unit tests for domain verification logic.

Do not use global variables.

Do not use GORM.

Follow idiomatic Go practices.

Output:

Complete project directory tree.

All Go source files.

Docker configuration.

Example .env file.

Instructions to run locally.

Example API requests and responses.
