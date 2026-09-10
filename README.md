# DevSecOps End-to-End POC (Hardened Baseline)

A complete, runnable DevSecOps pipeline demo: a Node.js/Express application,
wired into a single GitHub Actions pipeline that runs SAST (SonarQube), SCA,
secret scanning, container/IaC scanning, SBOM generation, and DAST — with
real pass/fail security gates at every stage. Images are pushed to
**Amazon ECR** and deployed via **Docker Compose over SSH**.

> This is the **hardened** edition of the app — no intentional vulnerabilities.
> Use it to validate the pipeline mechanics themselves (secrets, gates, DAST
> against a real public IP, approval flow) and see genuine PASS results.
> See `docs/HARDENED_BASELINE.md` for exactly what was fixed and why, and
> for how to get the deliberately-vulnerable training edition back if you
> want to demo FAIL states on a separate branch.

## Repository structure

```
devsecops-poc/
├── app/                          # Hardened Node.js/Express application
│   ├── server.js                 # Parameterized queries, hashed passwords, escaped output, etc.
│   ├── package.json              # Current, patched dependency versions
│   ├── Dockerfile                # Multi-stage, non-root, current base image
│   ├── .env.example
│   └── public/welcome.txt
├── docker-compose.yml            # Local dev - builds from ./app + optional ZAP scan
├── docker-compose.prod.yml       # Deployed host - pulls the image from ECR
├── k8s/                          # Optional reference only - NOT used by pipeline.yml
│   ├── deployment.yaml           # Hardened K8s Deployment (non-root, secrets from K8s Secret, etc.)
│   └── service.yaml
├── iac/
│   └── main.tf                   # Hardened Terraform (private S3, restricted security group)
├── security/
│   ├── .gitleaks.toml            # Secret-scanning rules
│   ├── sonar-project.properties  # SonarQube SAST config
│   ├── dependency-check-suppression.xml
│   └── zap-rules.tsv             # DAST alert tuning
├── .github/workflows/
│   └── pipeline.yml              # Single combined CI+CD: secrets/SonarQube SAST/SCA/IaC/build/
│                                  # image/SBOM (on PR) -> ECR push/Compose deploy/DAST/promotion (on push)
└── docs/
    ├── HARDENED_BASELINE.md      # What was fixed vs. the original vulnerable training app
    ├── SECURITY_GATES.md         # Exact gate implementation per tool
    ├── SECRETS_AND_VARIABLES.md  # Every secret/variable needed + gh CLI commands
    ├── UI_SETUP_GUIDE.md         # Same setup, done entirely by clicking github.com
    ├── PROMOTION_GUIDE.md        # dev -> uat -> prod approval setup + gh commands to approve
    ├── AWS_ECR_SETUP.md          # OIDC role setup + pushing images to Amazon ECR
    ├── DOCKER_COMPOSE_DEPLOY.md  # SSH-based Docker Compose deployment setup
    ├── SONARQUBE_SETUP.md        # Running self-hosted SonarQube Community Edition
    ├── FLOW_DIAGRAM.md           # Mermaid diagram + step-by-step explanation
    └── POC_GUIDE.md              # From-scratch setup, Git commands, fix guide
```

## Quick start (local dev)

```bash
cd app
cp .env.example .env
# Edit .env and set JWT_SECRET to a real random value: openssl rand -hex 32
npm install
npm start
# App listens on http://localhost:3000
```

Or via Docker Compose (also spins up an optional ZAP scan):

```bash
docker compose up --build hardened-app
docker compose run zap        # runs a ZAP baseline scan against it
```

## Try it out

```bash
# Health check
curl http://localhost:3000/

# Login with a seeded user (password is hashed server-side, never stored plaintext)
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMe!123"}'

# Admin route now correctly enforces role, not just "any valid token"
curl http://localhost:3000/api/admin/users -H "Authorization: Bearer <token from /api/login>"

# XSS payload comes back HTML-escaped, not executed
curl "http://localhost:3000/api/greet?name=<script>alert(1)</script>"

# SQLi payload is treated as a literal string, not part of the query
curl "http://localhost:3000/api/users/search?username=' OR '1'='1"
```

## How the pipeline deploys

1. `build-and-push` builds the image and pushes it to **Amazon ECR** (OIDC auth, no long-lived AWS keys in GitHub) — see `docs/AWS_ECR_SETUP.md`.
2. `deploy` copies `docker-compose.prod.yml` to your VM and SSHes in to run `docker compose pull && up -d` — see `docs/DOCKER_COMPOSE_DEPLOY.md`.
3. `dast` runs OWASP ZAP against your public IP.

## Where to go next

1. **`docs/HARDENED_BASELINE.md`** — what changed and what to expect from each pipeline stage now.
2. **`docs/POC_GUIDE.md`** — the full from-scratch walkthrough (prerequisites, Git/GitHub setup, running the pipeline).
3. **`docs/SECURITY_GATES.md`** — exactly how each gate is enforced in the YAML.
4. **`docs/PROMOTION_GUIDE.md`** / **`docs/UI_SETUP_GUIDE.md`** — setting up dev → uat → prod approval gates (CLI or click-through).
5. **`docs/FLOW_DIAGRAM.md`** — the complete lifecycle diagram.
