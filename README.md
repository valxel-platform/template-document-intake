# template-document-intake

The Valxel template for **document intake**: people upload documents (a lab report, an
insurance card, a referral letter). The component checks them, reads the fields the product
needs through the LLM gateway, asks a person to review whatever it isn't sure of, and publishes
the fields as a data contract on Kafka.

```
browser ──presigned POST──▶ quarantine bucket
   │                              │  size · format by content · ClamAV
   └─ via BFF: declare, uploaded ─┤
                                  ▼
                    clean bucket (KMS) ──▶ extraction (LLM gateway) ──▶ sure? ──yes──▶ event
                                                                         └─no──▶ review queue ──▶ event
```

## What you write

- **`intake.yaml`:** the document types the product takes. For each type: allowed formats, size
  limit, retention, the dataset its fields are published under, and each field with whether it's
  required and the confidence below which a person reviews it. G4 reviews it with the design's
  *Documents* section.
- **`contracts/`** is written by the SDLC tool from the dataset catalog.

## API

| Call | Scope | What |
| --- | --- | --- |
| `POST /documents` | `documents:write` | Declare type, name, format and size. Returns the id and a 5-minute presigned POST |
| `POST /documents/{id}/uploaded` | `documents:write` (uploader) | The upload is done; checks start |
| `GET /documents/{id}` | `documents:read` | Status, and the fields once checked |
| `GET /documents/{id}/download` | `documents:read` | A one-minute link, only for a checked file |
| `GET /reviews` | `documents:review` | Documents waiting for a person |
| `POST /documents/{id}/review` | `documents:review` (not the uploader) | Confirm or correct fields; then they're published |

Every call is limited to the caller's tenants: anything else is 404. See [SECURITY.md](SECURITY.md).

## Ports

The API is on 8080, with `/healthz` and `/readyz` for Kubernetes' probes. `/metrics` is on the
management port, `MANAGEMENT_PORT` (8081), as Spring's actuator is in the Java templates. The
platform's metrics collector scrapes it there, and the product's mesh lets the collector reach that
port and no other. The API port serves no metrics.

## Running

```sh
uv sync
INTAKE_OIDC_ISSUER=... INTAKE_OIDC_JWKS_URL=... uv run document-intake   # memory storage, no scanner
uv run pytest      # VALXEL_TEST_DATABASE_URL=postgresql://... also runs the Postgres store tests
```

Deployed, set:
- storage: `INTAKE_STORAGE=s3`, `INTAKE_QUARANTINE_BUCKET`, `INTAKE_CLEAN_BUCKET`, `INTAKE_KMS_KEY_ID`;
- scanning: `INTAKE_SCANNER=clamd` (plus `INTAKE_CLAMD_HOST` and `INTAKE_CLAMD_PORT`);
- extraction: `INTAKE_GATEWAY_URL`, `INTAKE_GATEWAY_KEY`, `INTAKE_EXTRACTION_MODEL`;
- `INTAKE_DATABASE_URL` and `INTAKE_KAFKA_BOOTSTRAP`.

Staging and production refuse to start without the storage, scanner, database and Kafka settings.
