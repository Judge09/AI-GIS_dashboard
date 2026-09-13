# Azure Runbook — Generating the Code Llama 13B & DeepSeek-R1 14B Held-Out Corpora

This is the operator runbook for producing the LLM-generated adversarial
subsets specified in **Chapter 3, Section 3.5** on an Azure **CPU** VM running
Ollama. Every step you run yourself with your own Azure credentials — the
scripts are backend-agnostic and reach the VM through an SSH tunnel, so nothing
in the AI-GIS pipeline changes except one `--host` flag.

> **Why CPU, not GPU:** Azure for Students subscriptions have **no GPU (NC/ND)
> quota** and cannot allocate those SKUs. A general-purpose CPU VM runs
> quantized 13–14B models on CPU via Ollama — slower per batch, but the full
> run finishes in a few hours for a few dollars of the $100 student credit, and
> the scripts need zero changes. If you later get GPU quota, the GPU path is
> preserved as an alternative in step 1.

> **What this produces:** `~500 + 500` Code Llama payloads and `~300 + 300`
> DeepSeek payloads, validated, de-duplicated, and frozen with a run manifest
> (model tag + digest, seeds, per-family counts, acceptance rate). These are
> **held-out test data only** — never used for training, tuning, vocabulary, or
> threshold selection.

---

## 0. Cost, quota, and safety notes (read first)

- **Check your compute quota before provisioning.** Student subscriptions have
  no GPU quota; confirm you have room for the CPU VM below:

  ```bash
  # vCPU quota for the Dsv5 family in your region (need >= 8 free)
  az vm list-usage --location eastus \
    --query "[?contains(name.value,'DSv5') || contains(name.value,'Dsv5')].{Name:name.localizedValue, Current:currentValue, Limit:limit}" \
    -o table
  ```

- **Cost:** `Standard_D8s_v5` is ~US$0.38/hr (pay-as-you-go; often less with the
  student credit). A full run is a few hours = a few dollars. **`az vm deallocate`
  the moment you finish** — a running VM bills continuously even while idle.
- **Never expose Ollama's port 11434 to the internet.** It has no auth. This
  runbook reaches it only through an SSH tunnel, so the port stays bound to the
  VM's loopback.
- **Everything runs offline in the lab sense of Section 3.2:** payloads are
  generated on an isolated VM, validated locally, and never sent at a live
  system. The abliterated DeepSeek build is used only to produce this defensive
  test corpus, consistent with Section 3.11.

---

## 1. Provision a CPU VM

```bash
az group create --name aigis-gen-rg --location eastus

# D8s_v5: 8 vCPU / 32 GB RAM — enough to run one quantized 13–14B model at a
# time on CPU. Bump to D16s_v5 (16 vCPU / 64 GB) if you want ~2x throughput and
# have the quota + credit for it.
az vm create \
  --resource-group aigis-gen-rg \
  --name aigis-gen-vm \
  --image Ubuntu2204 \
  --size Standard_D8s_v5 \
  --os-disk-size-gb 64 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --nsg-rule SSH          # SSH only — no inbound 11434

AZ_IP=$(az vm show -d -g aigis-gen-rg -n aigis-gen-vm --query publicIps -o tsv)
echo "VM at $AZ_IP"
```

> `--os-disk-size-gb 64` gives room for both model files (~8 GB + ~9 GB at Q4)
> plus working space. The `--nsg-rule SSH` flag opens **only** port 22; port
> 11434 is never exposed — we tunnel it in step 4.
>
> **GPU alternative (only if you have NC-series quota):** swap
> `--size Standard_D8s_v5 --os-disk-size-gb 64` for
> `--size Standard_NC4as_T4_v3`, and in step 2 also install the NVIDIA driver
> (`sudo apt-get install -y ubuntu-drivers-common && sudo ubuntu-drivers install
> && sudo reboot`, then verify with `nvidia-smi`). Everything else is identical.

---

## 2. Install Ollama on the VM

```bash
ssh azureuser@$AZ_IP

# No GPU driver needed on a CPU VM — Ollama runs the models CPU-only.
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama

# sanity: server answers locally on the VM
curl -s http://localhost:11434/api/tags && echo "  <- Ollama up"
```

> **CPU inference is slower.** Expect roughly 1–3 minutes per 20-payload batch
> for a 13–14B model at Q4 on 8 vCPU. The smoke test in step 5 (`--batches 2`)
> lets you measure your actual rate before committing to the full run.

---

## 3. Pull the exact model tags (Section 3.5 preservation requirement)

```bash
# still on the VM
ollama pull codellama:13b

# DeepSeek — the ABLITERATED build the thesis names (ref [40]). The standard
# aligned DeepSeek-R1 refuses payload generation and will break the pipeline.
ollama pull huihui_ai/deepseek-r1-abliterated:14b-qwen-distill

ollama list        # copy the exact tags + digests into your lab notebook
```

> The digest is recorded automatically into each run manifest, but note it here
> too — it is the authoritative "which exact build produced this corpus" record.
>
> **On a 32 GB CPU VM, run the models one at a time** (step 5 then step 6, not
> in parallel). Both tags default to Q4_K_M quantization, which is what you want
> for CPU — each needs ~10–12 GB resident. Ollama unloads an idle model after a
> few minutes, so sequential runs are fine; concurrent runs risk OOM.

---

## 4. Open an SSH tunnel from your workstation

Run this in a separate terminal on the machine that has the AI-GIS repo. Leave
it open for the whole run.

```bash
# maps localhost:11434 on your machine -> 127.0.0.1:11434 on the VM
ssh -N -L 11434:localhost:11434 azureuser@$AZ_IP
```

Now `--host localhost --port 11434` (the script defaults) reaches the VM.
Verify from the repo machine:

```bash
curl -s http://localhost:11434/api/tags | head -c 300
```

---

## 5. Generate the Code Llama subset (~500 SQLi + ~500 XSS)

From `dashboard/` on your workstation:

```bash
# smoke test first — 2 batches, confirm output looks right before spending hours
python scripts/25_generate_codellama_corpus.py --model codellama:13b --batches 2

# full run
python scripts/25_generate_codellama_corpus.py --model codellama:13b
```

Produces:

- `data/eval/codellama_holdout.csv` — accepted payloads (frozen)
- `data/eval/codellama_rejects.csv` — rejects + reason (for the count report)
- `data/eval/codellama_run_manifest.json` — tag, digest, seeds, family counts,
  acceptance rate

---

## 6. Generate the DeepSeek subset (~300 SQLi + ~300 XSS, two-round)

Section 3.5's Round 2 feeds matched ModSecurity **PL1** rule IDs back to the
model. Stand up the **PL1** feedback WAF on port **8081** using the committed
compose file (kept distinct from the **PL2** evaluation WAF on 8080 so the two
never collide). It reuses the backend + network the PL2 stack creates, so bring
PL2 up first:

```bash
# from the repo root
docker network create modsec-net 2>/dev/null || true
docker compose -f deploy/docker-compose.yml up -d                                  # PL2 stack -> creates backend + net
docker compose -f deploy/docker-compose.pl1.yml up -d        # PL1 feedback WAF on 8081

# confirm it answers (403 on an obvious attack, 200 on benign)
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8081/?q=1'%20OR%20'1'='1"
```

> The PL1 WAF runs **blocking** on purpose: the generator's Round-2 signal is
> the 403 + matched rule IDs. A DetectionOnly engine returns 200 and writes
> matches only to the stdout audit log, which the script can't read. This does
> not change the disclosed circularity — PL1 feedback, PL2 scoring.

Then, from `dashboard/`:

```bash
python scripts/26_generate_deepseek_corpus.py \
  --model huihui_ai/deepseek-r1-abliterated:14b-qwen-distill \
  --host localhost --modsec-host localhost --modsec-port 8081
```

No WAF available? Run Round-1-only and disclose it:

```bash
python scripts/26_generate_deepseek_corpus.py --model <tag> --no-round2
```

Produces `deepseek_holdout.csv`, `deepseek_rejects.csv`,
`deepseek_run_manifest.json`. The manifest records `round2_enabled`,
`round2_mutations_applied`, and the disclosed-circularity note verbatim.

---

## 7. Assemble the ~2,200-row benchmark and evaluate

```bash
# merge Code Llama + DeepSeek + held-out benign into one labelled CSV
python scripts/27_assemble_llm_holdout.py --benign-target 600

# score AI-GIS on it (headline detection / FPR)
python scripts/17_evaluate_csv.py --csv data/eval/llm_holdout_full.csv \
       --out reports/llm_holdout_results.json

# per-attack-type + generator segmentation (RQ2)
python scripts/19_eval_by_type.py --csv data/eval/llm_holdout_full.csv

# like-for-like ModSecurity PL2 baseline on the SAME rows (RQ3)
docker compose -f deploy/docker-compose.yml up -d          # the PL2 eval WAF on 8080
python scripts/21_modsec_holdout.py --csv data/eval/llm_holdout_full.csv \
       --host localhost --port 8080 --out reports/modsec_llm_holdout.json
```

> **Benign shortfall:** the repo currently ships 198 hard-benign rows, not 600.
> `27_*` uses what exists and prints the shortfall rather than fabricating
> traffic. To reach 600, generate more benign HTTP requests via the
> Flask/httperf procedure in Section 3.4.1.1 and append them to the benign
> source before assembling.

---

## 8. Tear down (do not skip)

```bash
docker compose -f deploy/docker-compose.pl1.yml down
docker compose -f deploy/docker-compose.yml down
az vm deallocate -g aigis-gen-rg -n aigis-gen-vm      # stops compute billing
# when fully done:
az group delete -n aigis-gen-rg --yes --no-wait
```

---

## What to report in Chapter 4

Read straight from the manifests and result JSONs — every figure is preserved:

| Report line | Source |
|---|---|
| Accepted vs rejected counts, per generator | `*_run_manifest.json` → `accepted`, `rejected_total`, `acceptance_rate` |
| Model tag + digest (provenance) | `*_run_manifest.json` → `model_tag`, `model_digest` |
| Per-family payload counts | `codellama_run_manifest.json` → `family_counts` |
| Round-2 mutations applied | `deepseek_run_manifest.json` → `round2_mutations_applied` |
| **Code Llama vs DeepSeek, reported separately** | `19_eval_by_type.py` output, split by the `generator` column |
| AI-GIS detection / FPR on the LLM corpus | `reports/llm_holdout_results.json` |
| ModSecurity PL2 on the identical rows | `reports/modsec_llm_holdout.json` |

Keep the two generators disaggregated in every table — the DeepSeek Round-2
circularity means the Code Llama subset is the clean, non-circular measurement
of the detection gap.
```
