<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 Contributors

  DISCLAIMER: THIS FILE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS HAVE ANY RESPONSIBILITY
  OR LIABILITY FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY ARISING FROM, OUT OF,
  OR IN CONNECTION WITH THIS FILE OR THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.
-->

# ADK Attestation Ledger — Interactive Architecture Simulator

[![License: MIT](https://img.shields.io/badge/License-MIT-38bdf8.svg)](./LICENSE)

> **Disclaimer:** This software and documentation are provided **"AS IS"**, without warranty of any kind, express or implied. The authors and copyright holders assume **no responsibility or liability** for any claim, damages, or other liability arising from, out of, or in connection with this software or its use. See the [LICENSE](./LICENSE) file for full details.

An interactive 3-panel visual simulator and cryptographic inspector explaining how the **Agent Development Kit (ADK) Attestation Ledger** decouples probabilistic Large Language Model (LLM) reasoning from deterministic execution authority.

---

## Why Traditional Software Trust Breaks Down with LLMs

Traditional microservices rely on ambient credentials (IAM roles, OAuth tokens, mTLS certificates) attached to a process because deterministic code only executes paths explicitly written by engineers.

Large Language Models (LLMs), however, are **probabilistic** and process untrusted natural-language inputs alongside system instructions. This exposes agents to:
- **Prompt Injection:** Untrusted data (emails, web pages, RAG documents) hijacking the agent's control flow to invoke destructive tools (`DROP TABLE`, unauthorized transfers).
- **Hallucinated Parameters:** Probabilistic token generation synthesizing plausible-looking but invalid or out-of-policy tool arguments.
- **Lateral Movement & Replay Attacks:** Compromised pods or network interceptors invoking downstream APIs directly or replaying previously captured approval tokens.

The **ADK Attestation Ledger** solves this by treating the LLM strictly as an *untrusted proposer* and requiring a verifiable **Cryptographic Action Receipt** anchored in an append-only transparency ledger before any downstream state change is committed.

---

## Core Architectural Concepts Visualized

### 1. Cryptographic Action Receipts (The 4 Pillars)
Whenever an agent requests a tool execution, the ADK Runtime intercepts the call and assembles a signed receipt capturing four cryptographic pillars:
1. **Agent Identity (`Ed25519` / `SPIFFE SVID`):** Binds the tool invocation to a hardware- or KMS-backed asymmetric key (`Ed25519`) and workload identity (`spiffe://example.com/ns/adk-prod/sa/...`).
2. **Input/Output Digests (`SHA-256`):** Cryptographic hashes of the prompt context, canonicalized tool parameters, and response payload so parameters cannot be altered in transit.
3. **Policy Decision Proof (`ALLOW` / `DENY`):** A deterministic policy gateway (e.g., Cedar / OPA) evaluates hard security invariants outside the LLM and co-signs the verdict.
4. **Liveness Proofs (`RFC 9334 RATS`):** High-entropy freshness nonces and strict millisecond Time-To-Live (TTL) windows bound to the verifier's challenge to prevent replay attacks.

### 2. Hash-Chained & Merkle Architecture (`IETF SCITT`)
- Every receipt includes `prev_receipt_hash`, forming an immutable hash chain.
- Receipts are hashed as leaves ($L_0 \dots L_3$) into a binary **Merkle Tree** backed by an **IETF SCITT** (Supply Chain Integrity, Transparency, and Trust) transparency log.
- Using **Merkle Math** ($O(\log N)$ inclusion proofs), a downstream verifier only needs the target leaf hash and its sibling audit path (`[L2, N01]`) to recompute and verify the signed Merkle Root.

### 3. Independent Downstream Verifiability
Downstream systems (**Database Write-Proxies**, **Kubernetes Admission Controllers**, **Enterprise API Gateways**) do not trust the agent's runtime environment. They independently verify:
- Agent Passport `Ed25519` signature
- `SHA-256` wire payload digest match
- Policy Gateway `ALLOW` co-signature
- `RFC 9334 RATS` nonce freshness and single-use registry status
- `SCITT` Merkle Root inclusion proof

---

## Interactive Features

- **5 Interactive Security Scenarios:**
  1. **Authorized Tool Call:** Full 7-step happy path with all 5 mathematical checks passing.
  2. **Prompt Injection Attack:** Indirect prompt injection attempting `DROP TABLE` blocked by the Deterministic Policy Gateway (`DENY`).
  3. **Replay Attack (Stale Nonce):** Captured `ALLOW` receipt replayed 92 seconds later, rejected by RFC 9334 RATS freshness check.
  4. **Lateral Movement (Forged Key):** Compromised adjacent workload calling the proxy without a valid SPIFFE/Ed25519 Agent Passport signature.
  5. **Merkle / Payload Tampering:** Man-in-the-middle modifying wire parameters after signing, triggering an immediate SHA-256 and Merkle Root mismatch cascade.
- **Live Wire Payload Tamper Editor & Merkle Tree Inspector:** Edit raw JSON tool parameters or click any leaf node ($L_0$–$L_3$) in the SVG Merkle tree to watch SHA-256 hashes recompute in real time.
- **Trust Model Comparison Toggle:** Switch between *Traditional Ambient IAM* (vulnerable) and *ADK Attestation Ledger* (cryptographically gated).
- **Downstream Verifier Target Switcher:** Inspect enforcement across a **Database Write-Proxy**, **Kubernetes Admission Controller**, or **Enterprise API Gateway**.

---

## Project Structure

```text
.
├── LICENSE                                 # MIT License with AS-IS / No-Liability clause
├── README.md                               # Architecture & usage documentation
├── index.html                              # Vite entry point with strict CSP headers
├── package.json                            # React 18, Vite 6, Lucide React dependencies
├── vite.config.js                          # Bound to 127.0.0.1:5173
├── adk-attestation-ledger-standalone.html  # Zero-dependency single-file HTML bundle
└── src/
    ├── main.jsx                            # React root mount
    ├── App.jsx                             # 3-panel interactive simulator & SVG diagrams
    ├── App.css                             # Dark-mode glassmorphic layout & animations
    └── ledgerData.js                       # Deterministic SHA-256 engine, Merkle tree & scenarios
```

---

## Getting Started

### Option 1: Run the Vite + React Development Server

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the local development server (bound to `127.0.0.1:5173`):**
   ```bash
   npm run dev
   ```
   Open [http://127.0.0.1:5173/](http://127.0.0.1:5173/) in your browser.

3. **Build for production:**
   ```bash
   npm run build
   ```

### Option 2: Open the Zero-Dependency Standalone Bundle

You can also open `adk-attestation-ledger-standalone.html` directly in any browser without Node.js or a build step:
```bash
open adk-attestation-ledger-standalone.html
```

---

## License & Disclaimer

Licensed under the **MIT License** (see [LICENSE](./LICENSE)).

```text
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
