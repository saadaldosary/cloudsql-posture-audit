# Cloud SQL Posture Audit

A fast, production-ready **Cloud SQL security & configuration posture audit script** for Google Cloud Platform.

Designed for:
- Cloud Security reviews
- Architecture assessments
- Compliance & audit evidence
- Platform engineering baselines

---

## 🚀 Features

- Audits **all Cloud SQL instances** in a project or across projects
- Automatically **skips projects without Cloud SQL Admin API**
- Zero hanging pipes – JSON fetched once, evaluated locally
- Human-readable **table output**
- Optional **CSV export**

---

## 🔍 What It Checks

- High Availability (HA vs Zonal)
- Public IP exposure
- Authorized networks
- Backups enabled
- Point-in-Time Recovery (PITR)
- SSL enforcement
- Deletion protection
- Disk size & machine tier
- Replicas count
- Database engine & version
- Edition (Enterprise / Plus where available)

---

## 🚨 Findings Generated

Each instance is flagged with explicit findings such as:

- `NON_HA`
- `PUBLIC_IP`
- `NO_BACKUPS`
- `NO_PITR`
- `NO_SSL`
- `NO_DEL_PROTECT`
- `AUTH_NETS_SET`

Instances with no issues are marked as `OK`.

---

## 🧩 Requirements

- Google Cloud SDK (`gcloud`)
- `jq`
- `column` (optional, for prettier tables)

```bash
gcloud --version
jq --version
