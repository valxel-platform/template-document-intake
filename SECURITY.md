# Security policy

## Reporting a vulnerability

Do not open a public issue. Use **Security > Report a vulnerability** on this repository
(GitHub private vulnerability reporting), or email the product's security team. Include what you
found, how to reproduce it, and the impact you expect. We acknowledge reports within two
business days.

## What this repository does by default

- Secret scanning with push protection; Dependabot alerts and security updates.
- CodeQL code scanning on every pull request; merges are blocked on new high or critical alerts.
- Dependency review on pull requests; vulnerable additions at the platform's threshold block.
- The default branch is protected: pull requests only, code-owner review, required checks.

## Handling sensitive data

This repository may belong to a product that handles PHI or payment data. Never commit real
patient or cardholder data, including in tests, fixtures, logs or screenshots. Use synthetic
data. Do not log request bodies, identifiers or tokens.

## Access controls in document intake

- **Who:** every call needs a JWT from the product's IdP (audience: this service), passed on by
  the BFF. It is checked before any body is read. Scopes separate uploading (`documents:write`),
  reading (`documents:read`) and reviewing (`documents:review`), and nobody reviews their own upload.
- **Whose:** every document belongs to one tenant, taken from the uploader's token. A caller sees,
  downloads and reviews only their tenants' documents; any other document answers 404.
- **Uploads:** a presigned POST to a quarantine bucket. It lasts 5 minutes and covers one key, the
  declared Content-Type and at most the type's size. Files are stored by id, never by name.
- **Checks before anything reads a file:** size, format by content (magic bytes, never the name or
  the browser's Content-Type) and a malware scan. A scan that can't run never counts as clean.
  Infected or wrong files are deleted at once.
- **At rest:** checked files move to a separate bucket encrypted with the product's KMS key. A
  download is a one-minute presigned GET, given only for a checked file.
- **Extraction** goes through the product's LLM gateway, which decides which models the data
  class allows. Only the expected fields are kept, as bounded strings.
- **Audit:** declaring, scanning, rejecting, extracting, reading, downloading, reviewing and purging
  are all recorded by document id, never with a field's value. For PHI and payments, nothing is
  answered without its record.
- **Retention:** documents are purged after their type's `retention_days`.
- Staging and production refuse to start with in-memory storage, without the scanner, without
  Postgres or without Kafka.
