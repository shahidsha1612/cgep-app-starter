# Acme Health — Patient Intake API (SOC 2 GRC Capstone)

Fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter):
a deliberately-flawed telehealth intake API, wrapped with a Terraform GRC
baseline, an OPA/Rego policy gate, a signing GitHub Actions pipeline, and an
OSCAL component -- built against **SOC 2 Trust Services Criteria** as the
declared primary framework (see `WRITEUP.md`).

## Verify in about five minutes

**1. Fork lineage**
```bash
gh repo view shahidsha1612/cgep-capstone --json fork,parent
# -> "fork": true, "parent": {"full_name": "GRCEngClub/cgep-app-starter"}
```

**2. Deploy gate** (the starter's own workload, still present and runnable)
```bash
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
# -> {"submission_id": "...", "status": "received"}
```

**3. Policy suite**
```bash
opa test ./policies
# -> PASS: 15/15

cd terraform
terraform plan -out=tfplan && terraform show -json tfplan > tfplan.json
conftest test tfplan.json -p ../policies --all-namespaces
# -> 6 tests, 6 passed
```

**4. Pipeline** -- `.github/workflows/grc-gate.yml`. Check the repo's Actions
tab and pull request history for one PR that passed the gate and merged, and
one that was blocked by it.

**5. Signed evidence chain**
```bash
scripts/verify-evidence.sh
# -> CHAIN INTACT
```

**6. OSCAL component**
```bash
oscal/components/acme-health-intake.json
# validated with NIST's trestle CLI and the official OSCAL JSON schema
# -- see oscal/README.md for exact commands and results.
```

**7. Full reasoning** -- framework choice, gap-by-gap remediation, design
trade-offs, and what's left open: `WRITEUP.md`.

## Layout

```
cgep-capstone/
├── README.md                    # this file
├── WRITEUP.md                   # graded reasoning document
├── WORKLOAD.md                  # what the starter API does
├── GAPS.md                      # the 8 named gaps (starter, unmodified)
├── FRAMEWORKS.md                # HIPAA / SOC 2 / CMMC mapping primer (starter, unmodified)
├── Makefile                     # make deploy | test | destroy
├── terraform/
│   ├── main.tf                  # starter app + KMS, evidence vault, CloudTrail, gap fixes
│   ├── variables.tf / outputs.tf
│   └── lambda/handler.py        # starter app code, unmodified
├── policies/
│   ├── *.rego                   # 6 SOC 2 gap-detection policies
│   └── tests/*_test.rego        # opa test fixtures (15/15 passing)
├── scripts/
│   └── verify-evidence.sh       # Cosign + SHA-256 + Object Lock check -> CHAIN INTACT
├── .github/workflows/
│   └── grc-gate.yml             # Plan -> Policy check -> Apply -> Sign -> Upload
├── oscal/
│   ├── components/acme-health-intake.json
│   └── README.md                 # validation commands + results
└── closing-meeting/              # stakeholder-facing status docs
```

## Cost

Roughly $0 if destroyed within a day. Lambda + API Gateway + DynamoDB + S3
are pay-per-use; CloudTrail and the evidence vault cost cents. `make
destroy` tears everything down (note: evidence vault objects are under
Object Lock in GOVERNANCE mode with a short retention window, so destroy
may need to wait out or bypass retention on those specific objects).

## License

MIT. Fork freely. Submission remains the author's own work.
