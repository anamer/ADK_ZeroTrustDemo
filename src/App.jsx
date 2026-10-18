/**
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Contributors
 *
 * DISCLAIMER: THIS FILE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS HAVE ANY RESPONSIBILITY
 * OR LIABILITY FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY ARISING FROM, OUT OF,
 * OR IN CONNECTION WITH THIS FILE OR THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Key,
  Hash,
  FileCheck2,
  Clock,
  GitMerge,
  Server,
  Play,
  Pause,
  RotateCcw,
  ChevronRight,
  ChevronLeft,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Sparkles,
  Terminal,
  Flame,
  Eye,
  Layers,
  Zap
} from 'lucide-react';
import {
  sha256Hex,
  LIFECYCLE_STEPS,
  DOWNSTREAM_TARGETS,
  SCENARIOS,
  INITIAL_HISTORICAL_RECEIPTS,
  buildLedgerAndMerkleTree
} from './ledgerData.js';

// Mask email PII in default UI badges per secure frontend data handling guidelines
// TODO(security): Authentication context shown in simulator is read-only educational metadata;
// production deployments must rely on HttpOnly, Secure, SameSite=Strict session cookies via a BFF.
function formatMaskedIdentity(showFull) {
  return showFull ? 'admin@example.com' : 'ad***@example.com';
}

export default function App() {
  // Layout splitter state
  const [leftWidth, setLeftWidth] = useState(330);
  const [rightWidth, setRightWidth] = useState(410);
  const isDraggingLeft = useRef(false);
  const isDraggingRight = useRef(false);

  // Simulator state
  const [currentStep, setCurrentStep] = useState(7);
  const [isAutoPlaying, setIsAutoPlaying] = useState(false);
  const [selectedScenarioId, setSelectedScenarioId] = useState('authorized');
  const [selectedTargetId, setSelectedTargetId] = useState('db_proxy');
  const [activeRightTab, setActiveRightTab] = useState('receipt_json');
  const [selectedMerkleLeafIdx, setSelectedMerkleLeafIdx] = useState(3);
  const [trustComparisonMode, setTrustComparisonMode] = useState('attestation'); // 'traditional' | 'attestation'
  const [showFullEmail, setShowFullEmail] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);

  // Interactive editable state for live SHA-256 & tamper testing
  const [customWirePayload, setCustomWirePayload] = useState('');
  const [isWireTamperedManually, setIsWireTamperedManually] = useState(false);
  const [historicalReceipts, setHistoricalReceipts] = useState(INITIAL_HISTORICAL_RECEIPTS);

  const currentScenario = useMemo(
    () => SCENARIOS.find((s) => s.id === selectedScenarioId) || SCENARIOS[0],
    [selectedScenarioId]
  );
  const currentTarget = DOWNSTREAM_TARGETS[selectedTargetId];

  // Sync wire payload when scenario or target changes
  useEffect(() => {
    const baseParams = currentScenario.toolParamsByTarget[selectedTargetId];
    const wireOverride =
      currentScenario.tamperedWireOverrideByTarget &&
      currentScenario.tamperedWireOverrideByTarget[selectedTargetId];
    setCustomWirePayload(wireOverride || baseParams);
    setIsWireTamperedManually(Boolean(wireOverride));

    if (selectedScenarioId === 'merkle_tamper') {
      setHistoricalReceipts((prev) =>
        prev.map((r, idx) =>
          idx === 1
            ? {
                ...r,
                tamperedPayloadSummary:
                  '{"sandbox":"python-isolation:v1.4.2","script_sha256":"TAMPERED_MALICIOUS_HASH_000000"}'
              }
            : { ...r, tamperedPayloadSummary: null }
        )
      );
    } else {
      setHistoricalReceipts(INITIAL_HISTORICAL_RECEIPTS.map((r) => ({ ...r })));
    }
  }, [selectedScenarioId, selectedTargetId, currentScenario]);

  // Auto-play timer for protocol lifecycle stepper
  useEffect(() => {
    if (!isAutoPlaying) return undefined;
    const timer = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= LIFECYCLE_STEPS.length) {
          setIsAutoPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 2200);
    return () => clearInterval(timer);
  }, [isAutoPlaying]);

  // Mouse drag handlers for resizable vertical splitters
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (isDraggingLeft.current) {
        const nextWidth = Math.max(260, Math.min(480, e.clientX));
        setLeftWidth(nextWidth);
      } else if (isDraggingRight.current) {
        const nextWidth = Math.max(320, Math.min(580, window.innerWidth - e.clientX));
        setRightWidth(nextWidth);
      }
    };
    const handleMouseUp = () => {
      isDraggingLeft.current = false;
      isDraggingRight.current = false;
      document.body.style.cursor = 'default';
      document.body.style.userSelect = 'auto';
    };
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  // Compute live cryptographic SHA-256 digests for the active receipt
  const signedToolParams = currentScenario.toolParamsByTarget[selectedTargetId];
  const promptDigest = useMemo(
    () => sha256Hex(currentScenario.promptContext),
    [currentScenario.promptContext]
  );
  const signedInputDigest = useMemo(() => sha256Hex(signedToolParams), [signedToolParams]);
  const liveWireDigest = useMemo(() => sha256Hex(customWirePayload), [customWirePayload]);
  const outputDigest = useMemo(
    () => sha256Hex(currentScenario.responsePayload),
    [currentScenario.responsePayload]
  );

  // Active Leaf (#3) in the SCITT Merkle Ledger
  const activeLeafEntry = useMemo(
    () => ({
      index: 3,
      receiptId: 'rcpt-scitt-0004',
      timestamp: currentScenario.livenessProof.issuedAt,
      agentSpiffe: currentScenario.agentIdentity.spiffeId,
      tool: currentTarget.toolName,
      target: currentTarget.name,
      verdict: currentScenario.policyProof.verdict,
      ratsNonce: currentScenario.livenessProof.ratsNonce.split(' ')[0],
      payloadSummary: signedToolParams,
      tamperedPayloadSummary:
        customWirePayload !== signedToolParams ? customWirePayload : null
    }),
    [currentScenario, currentTarget, signedToolParams, customWirePayload]
  );

  // Build hash-chained ledger and 4-leaf Merkle tree
  const merkleState = useMemo(
    () => buildLedgerAndMerkleTree(historicalReceipts, activeLeafEntry),
    [historicalReceipts, activeLeafEntry]
  );

  // Downstream Mathematical Verification Checks (5 independent proofs)
  const verificationChecks = useMemo(() => {
    const checkIdentity =
      currentScenario.agentIdentity.signatureValid &&
      currentScenario.agentIdentity.spiffeId.startsWith('spiffe://example.com/');
    const checkInputDigest = signedInputDigest === liveWireDigest;
    const checkPolicy =
      currentScenario.policyProof.verdict === 'ALLOW' &&
      currentScenario.policyProof.policySignatureValid;
    const checkLiveness = currentScenario.livenessProof.nonceFresh;
    const checkMerkle = merkleState.rootValid;

    const allPassed =
      checkIdentity && checkInputDigest && checkPolicy && checkLiveness && checkMerkle;

    return {
      checkIdentity,
      checkInputDigest,
      checkPolicy,
      checkLiveness,
      checkMerkle,
      allPassed
    };
  }, [currentScenario, signedInputDigest, liveWireDigest, merkleState.rootValid]);

  // Selected leaf for Merkle Inclusion Proof highlighting
  const activeMerkleLeaf =
    merkleState.leaves[selectedMerkleLeafIdx] || merkleState.leaves[3];
  const siblingLeafIdx =
    selectedMerkleLeafIdx % 2 === 0
      ? selectedMerkleLeafIdx + 1
      : selectedMerkleLeafIdx - 1;
  const siblingLeaf = merkleState.leaves[siblingLeafIdx] || merkleState.leaves[2];
  const parentBranchIdx = Math.floor(selectedMerkleLeafIdx / 2);
  const cousinBranchIdx = parentBranchIdx === 0 ? 1 : 0;

  // Full untruncated Cryptographic Action Receipt JSON
  const fullReceiptJson = useMemo(() => {
    const leaf3 = merkleState.leaves[3];
    return JSON.stringify(
      {
        scitt_envelope_version: 'draft-ietf-scitt-architecture-09',
        receipt_id: 'rcpt-scitt-0004',
        adk_runtime_region: 'us-central1',
        gcp_project_id: 'acme-adk-prod',
        decoupled_execution_target: {
          service: currentTarget.name,
          endpoint: currentTarget.endpoint,
          tool_invoked: currentTarget.toolName
        },
        pillar_1_agent_identity: {
          spiffe_svid: currentScenario.agentIdentity.spiffeId,
          signature_algorithm: currentScenario.agentIdentity.keyAlgorithm,
          cloud_kms_key_uri: currentScenario.agentIdentity.kmsKeyUri,
          public_key_fingerprint: currentScenario.agentIdentity.publicKeyFingerprint,
          ed25519_signature_hex: `0x${sha256Hex(
            currentScenario.agentIdentity.spiffeId + signedInputDigest
          )}${sha256Hex('ed25519-sig-tail').slice(0, 32)}`,
          signature_verified: verificationChecks.checkIdentity
        },
        pillar_2_io_digests: {
          hash_algorithm: 'SHA-256 (FIPS 180-4)',
          prompt_context_sha256: promptDigest,
          signed_tool_params_sha256: signedInputDigest,
          wire_received_params_sha256: liveWireDigest,
          response_payload_sha256: outputDigest,
          digest_integrity_match: verificationChecks.checkInputDigest
        },
        pillar_3_policy_decision_proof: {
          policy_engine: currentScenario.policyProof.engine,
          policy_rule_id: currentScenario.policyProof.policyId,
          signed_verdict: currentScenario.policyProof.verdict,
          invariants_evaluated: currentScenario.policyProof.invariantsChecked,
          policy_engine_signature_hex: `0x${sha256Hex(
            currentScenario.policyProof.policyId + currentScenario.policyProof.verdict
          )}`,
          verdict_allows_execution: verificationChecks.checkPolicy
        },
        pillar_4_liveness_proof: {
          standard: 'RFC 9334 RATS (Remote Attestation Procedures)',
          freshness_nonce: currentScenario.livenessProof.ratsNonce,
          issued_at_rfc3339: currentScenario.livenessProof.issuedAt,
          expires_at_rfc3339: currentScenario.livenessProof.expiresAt,
          observed_age_ms: currentScenario.livenessProof.clockSkewMs,
          max_ttl_ms: 15000,
          liveness_verified: verificationChecks.checkLiveness
        },
        scitt_merkle_inclusion_proof: {
          tree_algorithm: 'RFC 9162 / IETF SCITT Binary Merkle Tree (SHA-256)',
          leaf_index: 3,
          tree_size: 4,
          prev_receipt_hash: leaf3.prevActualHash,
          expected_leaf_hash: leaf3.expectedLeafHash,
          actual_leaf_hash: leaf3.actualLeafHash,
          sibling_witness_hashes: [
            merkleState.leaves[2].actualLeafHash,
            merkleState.branches[0].actualHash
          ],
          signed_merkle_tree_root: merkleState.expectedRoot,
          recomputed_merkle_root: merkleState.actualRoot,
          merkle_inclusion_valid: verificationChecks.checkMerkle
        },
        downstream_verifier_decision: {
          verifier: currentTarget.verifierMechanism,
          final_state_mutation_verdict: verificationChecks.allPassed
            ? 'COMMIT_STATE_CHANGE'
            : 'REJECT_AND_QUARANTINE'
        }
      },
      null,
      2
    );
  }, [
    currentScenario,
    currentTarget,
    promptDigest,
    signedInputDigest,
    liveWireDigest,
    outputDigest,
    merkleState,
    verificationChecks
  ]);

  const handleCopy = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const toggleTamperHistoricalReceipt = (idx) => {
    setHistoricalReceipts((prev) =>
      prev.map((item, i) => {
        if (i !== idx) return item;
        if (item.tamperedPayloadSummary !== null) {
          return { ...item, tamperedPayloadSummary: null };
        }
        return {
          ...item,
          tamperedPayloadSummary: item.payloadSummary.replace(
            /("table"|"sandbox"|"region"):\s*"[^"]+"/,
            '$1:"TAMPERED_BY_ATTACKER_0xDEAD"'
          )
        };
      })
    );
  };

  const handleTamperActiveWire = () => {
    if (customWirePayload !== signedToolParams) {
      setCustomWirePayload(signedToolParams);
      setIsWireTamperedManually(false);
    } else {
      const mutated = signedToolParams.replace(
        /("RECONCILED"|"500m"|42\.50|42\.5)/,
        '"TAMPERED_EXFIL_999999"'
      );
      setCustomWirePayload(
        mutated === signedToolParams
          ? `${signedToolParams.slice(0, -1)},"injected_override":true}`
          : mutated
      );
      setIsWireTamperedManually(true);
    }
  };

  const activeStepObj =
    LIFECYCLE_STEPS.find((s) => s.id === currentStep) || LIFECYCLE_STEPS[0];

  return (
    <div className="app-shell">
      {/* TOP HEADER BAR */}
      <header className="top-header">
        <div className="brand-block">
          <div className="brand-icon-wrap">
            <ShieldCheck className="icon-cyan" size={22} />
          </div>
          <div>
            <div className="brand-title-row">
              <h1 className="brand-title">ADK Attestation Ledger</h1>
              <span className="version-pill">SCITT + RFC 9334 RATS</span>
            </div>
            <p className="brand-subtitle">
              Decoupling Probabilistic LLM Reasoning from Deterministic Execution Authority
            </p>
          </div>
        </div>

        {/* Scenario / Attack Lab Selector */}
        <div className="scenario-bar" role="tablist" aria-label="Simulation Scenarios">
          {SCENARIOS.map((scen) => {
            const isActive = scen.id === selectedScenarioId;
            return (
              <button
                key={scen.id}
                type="button"
                onClick={() => {
                  setSelectedScenarioId(scen.id);
                  setCurrentStep(7);
                }}
                className={`scenario-tab ${isActive ? 'active' : ''} ${
                  scen.category === 'attack' ? 'is-attack' : 'is-safe'
                }`}
              >
                {scen.category === 'attack' ? (
                  <Flame size={13} className="tab-icon-attack" />
                ) : (
                  <CheckCircle2 size={13} className="tab-icon-safe" />
                )}
                <span>{scen.shortLabel}</span>
              </button>
            );
          })}
        </div>

        {/* Cloud Authentication & Environment Context Badge */}
        <div className="auth-context-group">
          <div className="target-select-wrap">
            <label htmlFor="target-selector" className="target-label">
              Downstream Verifier:
            </label>
            <select
              id="target-selector"
              className="target-select"
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
            >
              {Object.values(DOWNSTREAM_TARGETS).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            className="gcp-auth-badge"
            onClick={() => setShowFullEmail((v) => !v)}
            title="Click to toggle full/masked administrator identity"
          >
            <span className="status-dot-emerald" />
            <div className="auth-meta">
              <span className="auth-user">{formatMaskedIdentity(showFullEmail)}</span>
              <span className="auth-project">acme-adk-prod • us-central1</span>
            </div>
            <Eye size={13} className="auth-eye" />
          </button>
        </div>
      </header>

      {/* 3-PANEL RESIZABLE WORKBENCH */}
      <main className="workbench-grid">
        {/* LEFT PANEL: LIFECYCLE STEPPER & TRUST MODEL BREAKDOWN */}
        <aside className="panel left-panel" style={{ width: `${leftWidth}px` }}>
          <div className="panel-header">
            <div className="panel-title-group">
              <Layers size={16} className="icon-cyan" />
              <h2>Attestation Lifecycle</h2>
            </div>
            <span className="step-counter">
              Step {currentStep} / {LIFECYCLE_STEPS.length}
            </span>
          </div>

          {/* Playback Controls */}
          <div className="stepper-controls">
            <button
              type="button"
              className="ctrl-btn"
              onClick={() => {
                setIsAutoPlaying(false);
                setCurrentStep((s) => Math.max(1, s - 1));
              }}
              disabled={currentStep <= 1}
              title="Previous Step"
            >
              <ChevronLeft size={15} />
              <span>Back</span>
            </button>

            <button
              type="button"
              className={`ctrl-btn primary ${isAutoPlaying ? 'playing' : ''}`}
              onClick={() => {
                if (currentStep >= LIFECYCLE_STEPS.length && !isAutoPlaying) {
                  setCurrentStep(1);
                }
                setIsAutoPlaying((p) => !p);
              }}
            >
              {isAutoPlaying ? <Pause size={14} /> : <Play size={14} />}
              <span>{isAutoPlaying ? 'Pause' : 'Auto-Play'}</span>
            </button>

            <button
              type="button"
              className="ctrl-btn"
              onClick={() => {
                setIsAutoPlaying(false);
                setCurrentStep((s) => Math.min(LIFECYCLE_STEPS.length, s + 1));
              }}
              disabled={currentStep >= LIFECYCLE_STEPS.length}
              title="Next Step"
            >
              <span>Next</span>
              <ChevronRight size={15} />
            </button>

            <button
              type="button"
              className="ctrl-btn icon-only"
              onClick={() => {
                setIsAutoPlaying(false);
                setCurrentStep(7);
                setSelectedScenarioId('authorized');
              }}
              title="Reset to Authorized State"
            >
              <RotateCcw size={14} />
            </button>
          </div>

          {/* Stepper List */}
          <div className="stepper-list">
            {LIFECYCLE_STEPS.map((step) => {
              const isCurrent = step.id === currentStep;
              const isCompleted = step.id < currentStep;

              let stepAlert = false;
              if (step.id === 2 && !verificationChecks.checkIdentity) {
                stepAlert = true;
              } else if (step.id === 3 && !verificationChecks.checkInputDigest) {
                stepAlert = true;
              } else if (step.id === 4 && !verificationChecks.checkPolicy) {
                stepAlert = true;
              } else if (step.id === 5 && !verificationChecks.checkLiveness) {
                stepAlert = true;
              } else if (step.id === 6 && !verificationChecks.checkMerkle) {
                stepAlert = true;
              } else if (step.id === 7 && !verificationChecks.allPassed) {
                stepAlert = true;
              }

              return (
                <div
                  key={step.id}
                  onClick={() => {
                    setIsAutoPlaying(false);
                    setCurrentStep(step.id);
                  }}
                  className={`step-card ${isCurrent ? 'current' : ''} ${
                    isCompleted ? 'completed' : ''
                  } ${stepAlert ? 'step-alert' : ''}`}
                >
                  <div className="step-num-badge">
                    {stepAlert ? (
                      <AlertTriangle size={13} className="icon-rose" />
                    ) : isCompleted ? (
                      <Check size={13} />
                    ) : (
                      step.id
                    )}
                  </div>
                  <div className="step-card-body">
                    <div className="step-badge-row">
                      <span className="step-micro-badge">{step.badge}</span>
                      {stepAlert && <span className="step-violation-tag">VIOLATION</span>}
                    </div>
                    <div className="step-card-title">{step.shortTitle}</div>
                    <div className="step-card-actor">{step.actor}</div>
                    {isCurrent && (
                      <div className="step-expanded-notes">
                        <p>{step.summary}</p>
                        <div className="step-why-box">
                          <strong>Security Rationale:</strong> {step.whyItMatters}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Why Traditional Software Trust Breaks Down Card */}
          <div className="trust-breakdown-card">
            <div className="trust-card-header">
              <AlertTriangle size={15} className="icon-amber" />
              <h3>Why Traditional Trust Breaks Down</h3>
            </div>
            <p className="trust-card-desc">
              Traditional microservices assume deterministic code: if a service holds an IAM role, its queries are trusted. LLMs violate this invariant because reasoning is <strong>probabilistic</strong> and data mixes with instructions:
            </p>
            <ul className="trust-vuln-list">
              <li>
                <span className="vuln-dot rose" />
                <div>
                  <strong>Prompt Injection:</strong> Untrusted external text hijacks the LLM into issuing destructive tool calls.
                </div>
              </li>
              <li>
                <span className="vuln-dot amber" />
                <div>
                  <strong>Hallucination:</strong> Model fabricates SQL tables, parameters, or out-of-bounds quantities.
                </div>
              </li>
              <li>
                <span className="vuln-dot indigo" />
                <div>
                  <strong>Lateral Movement:</strong> Ambient container credentials allow compromised runtimes to pivot across databases.
                </div>
              </li>
            </ul>
          </div>
        </aside>

        {/* LEFT RESIZE SPLITTER */}
        <div
          className="splitter-bar"
          onMouseDown={() => {
            isDraggingLeft.current = true;
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
          }}
          title="Drag to resize left panel"
        />

        {/* CENTER PANEL: INTERACTIVE GRAPHICS, ARCHITECTURE PIPELINE, RECEIPT X-RAY & MERKLE TREE */}
        <section className="panel center-panel">
          {/* Active Scenario Banner & Trust Model Toggle */}
          <div
            className={`scenario-hero-banner ${
              verificationChecks.allPassed ? 'banner-safe' : 'banner-blocked'
            }`}
          >
            <div className="banner-left">
              <div className="banner-status-pill">
                {verificationChecks.allPassed ? (
                  <>
                    <ShieldCheck size={16} />
                    <span>EXECUTION AUTHORIZED BY MATHEMATICAL PROOF</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert size={16} />
                    <span>STATE MUTATION BLOCKED BY DOWNSTREAM VERIFIER</span>
                  </>
                )}
              </div>
              <h2 className="banner-title">{currentScenario.label}</h2>
              <p className="banner-desc">{currentScenario.description}</p>
            </div>

            <div className="banner-right-controls">
              <div className="trust-mode-toggle-box">
                <span className="toggle-caption">Compare Architecture Mode:</span>
                <div className="toggle-pill-group">
                  <button
                    type="button"
                    className={`mode-btn ${
                      trustComparisonMode === 'traditional' ? 'active-danger' : ''
                    }`}
                    onClick={() => setTrustComparisonMode('traditional')}
                  >
                    ❌ Traditional Ambient IAM
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${
                      trustComparisonMode === 'attestation' ? 'active-safe' : ''
                    }`}
                    onClick={() => setTrustComparisonMode('attestation')}
                  >
                    🛡️ ADK Attestation Ledger
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* 1. INTERACTIVE SVG ARCHITECTURE & DECOUPLING ILLUSTRATION */}
          <div className="viz-card">
            <div className="viz-card-header">
              <div className="viz-title-wrap">
                <Sparkles size={16} className="icon-cyan" />
                <h3>
                  {trustComparisonMode === 'attestation'
                    ? 'Decoupled Reasoning vs. Execution Authority Architecture (ADK Attestation Ledger)'
                    : 'Legacy Ambient Trust Model (Vulnerable to Prompt Injection & Lateral Movement)'}
                </h3>
              </div>
              <span className="viz-step-indicator">
                Active Focus: {activeStepObj.title}
              </span>
            </div>

            {trustComparisonMode === 'traditional' ? (
              <div className="traditional-warning-diagram">
                <svg
                  viewBox="0 0 920 215"
                  className="arch-svg"
                  role="img"
                  aria-label="Broken Traditional Trust Model Diagram"
                >
                  <defs>
                    <linearGradient id="dangerGrad" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#fb923c" stopOpacity="0.25" />
                    </linearGradient>
                  </defs>
                  <rect
                    x="15"
                    y="15"
                    width="890"
                    height="185"
                    rx="12"
                    fill="url(#dangerGrad)"
                    stroke="#f43f5e"
                    strokeDasharray="6 4"
                  />
                  <text x="35" y="42" fill="#fda4af" fontSize="12" fontWeight="700">
                    SINGLE AMBIENT TRUST ZONE (NO CRYPTOGRAPHIC DECOUPLING — REASONING ENGINE HAS DIRECT EXECUTION AUTHORITY)
                  </text>

                  {/* Node 1: Untrusted Prompt + Injection */}
                  <rect
                    x="35"
                    y="62"
                    width="220"
                    height="115"
                    rx="10"
                    fill="#161926"
                    stroke="#f43f5e"
                    strokeWidth="1.8"
                  />
                  <text x="52" y="88" fill="#f8fafc" fontSize="13" fontWeight="700">
                    1. Probabilistic LLM Agent
                  </text>
                  <text x="52" y="108" fill="#fda4af" fontSize="11">
                    • Susceptible to Prompt Injection
                  </text>
                  <text x="52" y="126" fill="#fda4af" fontSize="11">
                    • Hallucinates destructive SQL/API
                  </text>
                  <text x="52" y="144" fill="#fbbf24" fontSize="11">
                    • Holds Ambient Service Account!
                  </text>

                  {/* Unchecked Arrow */}
                  <line
                    x1="255"
                    y1="120"
                    x2="365"
                    y2="120"
                    stroke="#f43f5e"
                    strokeWidth="3"
                    strokeDasharray="6 4"
                  />
                  <polygon points="365,114 378,120 365,126" fill="#f43f5e" />
                  <text x="270" y="108" fill="#fda4af" fontSize="10" fontWeight="600">
                    Raw Bearer Token
                  </text>

                  {/* Node 2: Missing Attestation */}
                  <rect
                    x="378"
                    y="62"
                    width="215"
                    height="115"
                    rx="10"
                    fill="#2a1219"
                    stroke="#f43f5e"
                    strokeWidth="1.8"
                  />
                  <text x="394" y="88" fill="#fecdd3" fontSize="13" fontWeight="700">
                    2. No Action Receipt!
                  </text>
                  <text x="394" y="108" fill="#fda4af" fontSize="11">
                    ✗ No I/O SHA-256 Digest
                  </text>
                  <text x="394" y="126" fill="#fda4af" fontSize="11">
                    ✗ No Deterministic Policy Sig
                  </text>
                  <text x="394" y="144" fill="#fda4af" fontSize="11">
                    ✗ No RFC 9334 Nonce / Merkle Log
                  </text>

                  {/* Unchecked Arrow 2 */}
                  <line
                    x1="593"
                    y1="120"
                    x2="675"
                    y2="120"
                    stroke="#f43f5e"
                    strokeWidth="3"
                  />
                  <polygon points="675,114 688,120 675,126" fill="#f43f5e" />
                  <text x="602" y="108" fill="#fda4af" fontSize="10" fontWeight="600">
                    Blind Trust
                  </text>

                  {/* Node 3: Downstream compromised */}
                  <rect
                    x="688"
                    y="62"
                    width="195"
                    height="115"
                    rx="10"
                    fill="#3b0a14"
                    stroke="#f43f5e"
                    strokeWidth="2"
                  />
                  <text x="704" y="88" fill="#ffffff" fontSize="13" fontWeight="700">
                    3. {currentTarget.name}
                  </text>
                  <text x="704" y="110" fill="#fda4af" fontSize="11" fontWeight="700">
                    💥 CATASTROPHIC FAILURE:
                  </text>
                  <text x="704" y="128" fill="#fecdd3" fontSize="11">
                    Executes injected DROP TABLE,
                  </text>
                  <text x="704" y="146" fill="#fecdd3" fontSize="11">
                    replayed wire, or lateral pivot!
                  </text>
                </svg>
              </div>
            ) : (
              <div className="attestation-architecture-diagram">
                <svg
                  viewBox="0 0 960 310"
                  className="arch-svg"
                  role="img"
                  aria-label="ADK Attestation Ledger Decoupled Architecture Diagram"
                >
                  <defs>
                    <linearGradient id="untrustedZone" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.1" />
                      <stop offset="100%" stopColor="#0f172a" stopOpacity="0.3" />
                    </linearGradient>
                    <linearGradient id="attestationZone" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.12" />
                      <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.06" />
                    </linearGradient>
                    <linearGradient id="verifierZone" x1="0" y1="0" x2="0" y2="1">
                      <stop
                        offset="0%"
                        stopColor={verificationChecks.allPassed ? '#10b981' : '#f43f5e'}
                        stopOpacity="0.15"
                      />
                      <stop offset="100%" stopColor="#0f172a" stopOpacity="0.35" />
                    </linearGradient>
                  </defs>

                  {/* Zone 1: Untrusted Probabilistic Zone */}
                  <rect
                    x="12"
                    y="12"
                    width="225"
                    height="286"
                    rx="12"
                    fill="url(#untrustedZone)"
                    stroke="#f59e0b"
                    strokeOpacity="0.45"
                    strokeDasharray="5 4"
                  />
                  <text x="26" y="34" fill="#fbbf24" fontSize="10.5" fontWeight="700">
                    ZONE 1: PROBABILISTIC REASONING
                  </text>
                  <text x="26" y="48" fill="#94a3b8" fontSize="9.5">
                    Zero Ambient Execution Privileges
                  </text>

                  {/* LLM Node */}
                  <g
                    className={`svg-node ${currentStep === 1 ? 'node-focus' : ''}`}
                    onClick={() => setCurrentStep(1)}
                  >
                    <rect
                      x="26"
                      y="64"
                      width="196"
                      height="96"
                      rx="10"
                      fill="#131826"
                      stroke={currentStep === 1 ? '#38bdf8' : '#f59e0b'}
                      strokeWidth={currentStep === 1 ? '2.4' : '1.5'}
                    />
                    <text x="40" y="86" fill="#f8fafc" fontSize="12" fontWeight="700">
                      🧠 LLM Reasoning Engine
                    </text>
                    <text x="40" y="104" fill="#cbd5e1" fontSize="10.5">
                      Gemini 2.5 Pro (ADK Agent)
                    </text>
                    <text x="40" y="122" fill="#fbbf24" fontSize="10">
                      Emits Untrusted Action Intent
                    </text>
                    <text x="40" y="140" fill="#64748b" fontSize="9.5">
                      Tool: {currentTarget.toolName}
                    </text>
                  </g>

                  {/* Prompt Context Box */}
                  <rect
                    x="26"
                    y="182"
                    width="196"
                    height="98"
                    rx="10"
                    fill="#0d121f"
                    stroke="#334155"
                    strokeWidth="1.2"
                  />
                  <text x="40" y="202" fill="#94a3b8" fontSize="10.5" fontWeight="600">
                    Prompt & Context Input
                  </text>
                  <text x="40" y="220" fill="#38bdf8" fontSize="9.5" fontFamily="JetBrains Mono">
                    SHA256: {promptDigest.slice(0, 14)}...
                  </text>
                  <text
                    x="40"
                    y="240"
                    fill={currentScenario.category === 'attack' ? '#fda4af' : '#10b981'}
                    fontSize="10"
                    fontWeight="600"
                  >
                    Scenario: {currentScenario.shortLabel}
                  </text>
                  <text x="40" y="258" fill="#64748b" fontSize="9.5">
                    Click any node to inspect stage
                  </text>

                  {/* Trust Boundary Line 1 */}
                  <line
                    x1="248"
                    y1="14"
                    x2="248"
                    y2="296"
                    stroke="#38bdf8"
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                  />

                  {/* Zone 2: ADK Attestation & SCITT Control Plane */}
                  <rect
                    x="260"
                    y="12"
                    width="425"
                    height="286"
                    rx="12"
                    fill="url(#attestationZone)"
                    stroke="#06b6d4"
                    strokeOpacity="0.5"
                  />
                  <text x="276" y="34" fill="#38bdf8" fontSize="10.5" fontWeight="700">
                    ZONE 2: ADK ATTESTATION RUNTIME & SCITT TRANSPARENCY LEDGER
                  </text>
                  <text x="276" y="48" fill="#94a3b8" fontSize="9.5">
                    Mints Cryptographic Action Receipt (4 Pillars) + Merkle Inclusion Proof
                  </text>

                  {/* Pillar 1 & 2: Identity + Digests */}
                  <g
                    className={`svg-node ${
                      currentStep === 2 || currentStep === 3 ? 'node-focus' : ''
                    }`}
                    onClick={() => setCurrentStep(2)}
                  >
                    <rect
                      x="276"
                      y="64"
                      width="192"
                      height="96"
                      rx="10"
                      fill="#111827"
                      stroke={
                        !verificationChecks.checkIdentity || !verificationChecks.checkInputDigest
                          ? '#f43f5e'
                          : currentStep === 2 || currentStep === 3
                          ? '#38bdf8'
                          : '#0284c7'
                      }
                      strokeWidth="1.8"
                    />
                    <text x="290" y="85" fill="#f8fafc" fontSize="11.5" fontWeight="700">
                      🔑 1. Identity & 2. I/O Digests
                    </text>
                    <text x="290" y="103" fill="#7dd3fc" fontSize="9.5" fontFamily="JetBrains Mono">
                      Ed25519 + SPIFFE SVID
                    </text>
                    <text x="290" y="120" fill="#cbd5e1" fontSize="9.5" fontFamily="JetBrains Mono">
                      In: {signedInputDigest.slice(0, 14)}...
                    </text>
                    <text
                      x="290"
                      y="139"
                      fill={
                        verificationChecks.checkIdentity && verificationChecks.checkInputDigest
                          ? '#34d399'
                          : '#fda4af'
                      }
                      fontSize="10"
                      fontWeight="600"
                    >
                      {verificationChecks.checkIdentity && verificationChecks.checkInputDigest
                        ? '✓ KMS Sig & SHA-256 Valid'
                        : '✗ Identity / Digest Mismatch'}
                    </text>
                  </g>

                  {/* Pillar 3 & 4: Policy + Liveness */}
                  <g
                    className={`svg-node ${
                      currentStep === 4 || currentStep === 5 ? 'node-focus' : ''
                    }`}
                    onClick={() => setCurrentStep(4)}
                  >
                    <rect
                      x="478"
                      y="64"
                      width="192"
                      height="96"
                      rx="10"
                      fill="#111827"
                      stroke={
                        !verificationChecks.checkPolicy || !verificationChecks.checkLiveness
                          ? '#f43f5e'
                          : currentStep === 4 || currentStep === 5
                          ? '#38bdf8'
                          : '#6366f1'
                      }
                      strokeWidth="1.8"
                    />
                    <text x="492" y="85" fill="#f8fafc" fontSize="11.5" fontWeight="700">
                      ⚖️ 3. Policy & 4. RATS Nonce
                    </text>
                    <text
                      x="492"
                      y="103"
                      fill={
                        currentScenario.policyProof.verdict === 'ALLOW' ? '#34d399' : '#fda4af'
                      }
                      fontSize="10"
                      fontWeight="700"
                    >
                      Policy Verdict: {currentScenario.policyProof.verdict}
                    </text>
                    <text x="492" y="120" fill="#cbd5e1" fontSize="9.5" fontFamily="JetBrains Mono">
                      Nonce: {currentScenario.livenessProof.ratsNonce.slice(0, 14)}...
                    </text>
                    <text
                      x="492"
                      y="139"
                      fill={
                        verificationChecks.checkPolicy && verificationChecks.checkLiveness
                          ? '#34d399'
                          : '#fda4af'
                      }
                      fontSize="10"
                      fontWeight="600"
                    >
                      {verificationChecks.checkPolicy && verificationChecks.checkLiveness
                        ? '✓ Signed ALLOW + Fresh Nonce'
                        : '✗ Policy DENY or Stale Nonce'}
                    </text>
                  </g>

                  {/* Step 6: SCITT Hash-Chain & Merkle Tree Node */}
                  <g
                    className={`svg-node ${currentStep === 6 ? 'node-focus' : ''}`}
                    onClick={() => setCurrentStep(6)}
                  >
                    <rect
                      x="276"
                      y="182"
                      width="394"
                      height="98"
                      rx="10"
                      fill="#0f172a"
                      stroke={
                        !verificationChecks.checkMerkle
                          ? '#f43f5e'
                          : currentStep === 6
                          ? '#38bdf8'
                          : '#10b981'
                      }
                      strokeWidth="1.8"
                    />
                    <text x="292" y="204" fill="#f8fafc" fontSize="12" fontWeight="700">
                      🌳 IETF SCITT Transparency Log & Distributed Merkle Tree
                    </text>
                    <text x="292" y="223" fill="#94a3b8" fontSize="10.5">
                      Chains Receipt #3 to Prev Hash ({merkleState.leaves[3].prevActualHash.slice(0, 12)}...) & computes Merkle Inclusion Proof
                    </text>
                    <text x="292" y="242" fill="#38bdf8" fontSize="10" fontFamily="JetBrains Mono">
                      Signed Root: {merkleState.expectedRoot.slice(0, 22)}...
                    </text>
                    <text
                      x="292"
                      y="261"
                      fill={merkleState.rootValid ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontWeight="700"
                      fontFamily="JetBrains Mono"
                    >
                      Actual Root: {merkleState.actualRoot.slice(0, 22)}...{' '}
                      {merkleState.rootValid ? '[MERKLE PROOF VALID]' : '[HASH CHAIN BROKEN!]'}
                    </text>
                  </g>

                  {/* Zone 3: Downstream Zero-Trust Verifier */}
                  <rect
                    x="700"
                    y="12"
                    width="248"
                    height="286"
                    rx="12"
                    fill="url(#verifierZone)"
                    stroke={verificationChecks.allPassed ? '#10b981' : '#f43f5e'}
                    strokeWidth="1.8"
                  />
                  <text
                    x="716"
                    y="34"
                    fill={verificationChecks.allPassed ? '#34d399' : '#fda4af'}
                    fontSize="10.5"
                    fontWeight="700"
                  >
                    ZONE 3: INDEPENDENT VERIFIER
                  </text>
                  <text x="716" y="48" fill="#94a3b8" fontSize="9.5">
                    Zero Trust in Agent Runtime
                  </text>

                  <g
                    className={`svg-node ${currentStep === 7 ? 'node-focus' : ''}`}
                    onClick={() => setCurrentStep(7)}
                  >
                    <rect
                      x="714"
                      y="64"
                      width="220"
                      height="216"
                      rx="10"
                      fill="#111827"
                      stroke={verificationChecks.allPassed ? '#10b981' : '#f43f5e'}
                      strokeWidth="2"
                    />
                    <text x="728" y="88" fill="#ffffff" fontSize="12.5" fontWeight="700">
                      🛡️ {currentTarget.name}
                    </text>
                    <text x="728" y="105" fill="#94a3b8" fontSize="10">
                      {currentTarget.subtitle}
                    </text>

                    <text x="728" y="130" fill="#cbd5e1" fontSize="10.5" fontWeight="600">
                      Mathematical Checks:
                    </text>
                    <text
                      x="728"
                      y="148"
                      fill={verificationChecks.checkIdentity ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontFamily="JetBrains Mono"
                    >
                      {verificationChecks.checkIdentity ? '✓' : '✗'} 1. Ed25519 SVID Sig
                    </text>
                    <text
                      x="728"
                      y="165"
                      fill={verificationChecks.checkInputDigest ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontFamily="JetBrains Mono"
                    >
                      {verificationChecks.checkInputDigest ? '✓' : '✗'} 2. SHA-256 Wire Match
                    </text>
                    <text
                      x="728"
                      y="182"
                      fill={verificationChecks.checkPolicy ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontFamily="JetBrains Mono"
                    >
                      {verificationChecks.checkPolicy ? '✓' : '✗'} 3. Policy == ALLOW
                    </text>
                    <text
                      x="728"
                      y="199"
                      fill={verificationChecks.checkLiveness ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontFamily="JetBrains Mono"
                    >
                      {verificationChecks.checkLiveness ? '✓' : '✗'} 4. RFC 9334 Nonce TTL
                    </text>
                    <text
                      x="728"
                      y="216"
                      fill={verificationChecks.checkMerkle ? '#34d399' : '#fda4af'}
                      fontSize="10"
                      fontFamily="JetBrains Mono"
                    >
                      {verificationChecks.checkMerkle ? '✓' : '✗'} 5. SCITT Merkle Root
                    </text>

                    <rect
                      x="728"
                      y="232"
                      width="192"
                      height="34"
                      rx="6"
                      fill={verificationChecks.allPassed ? '#064e3b' : '#4c0519'}
                      stroke={verificationChecks.allPassed ? '#10b981' : '#f43f5e'}
                    />
                    <text
                      x="742"
                      y="253"
                      fill={verificationChecks.allPassed ? '#6ee7b7' : '#fda4af'}
                      fontSize="11"
                      fontWeight="700"
                    >
                      {verificationChecks.allPassed
                        ? 'STATE CHANGE COMMITTED'
                        : 'EXECUTION QUARANTINED'}
                    </text>
                  </g>

                  {/* Animated Connector Lines */}
                  <path
                    d="M 222 112 L 276 112"
                    stroke="#38bdf8"
                    strokeWidth="2.2"
                    strokeDasharray="5 3"
                    className="animated-flow-line"
                  />
                  <path
                    d="M 468 112 L 478 112"
                    stroke="#38bdf8"
                    strokeWidth="2.2"
                  />
                  <path
                    d="M 472 160 L 472 182"
                    stroke="#38bdf8"
                    strokeWidth="2.2"
                    strokeDasharray="4 3"
                    className="animated-flow-line"
                  />
                  <path
                    d="M 670 230 L 714 230"
                    stroke={verificationChecks.allPassed ? '#10b981' : '#f43f5e'}
                    strokeWidth="2.6"
                    strokeDasharray="6 3"
                    className="animated-flow-line"
                  />
                </svg>
              </div>
            )}
          </div>

          {/* 2. CRYPTOGRAPHIC ACTION RECEIPT ANATOMY (THE 4 PILLARS) */}
          <div className="viz-card">
            <div className="viz-card-header">
              <div className="viz-title-wrap">
                <FileCheck2 size={16} className="icon-cyan" />
                <h3>Cryptographic Action Receipt Anatomy (4-Pillar X-Ray)</h3>
              </div>
              <div className="header-actions">
                <button
                  type="button"
                  className={`tamper-action-btn ${
                    customWirePayload !== signedToolParams ? 'active' : ''
                  }`}
                  onClick={handleTamperActiveWire}
                >
                  <Zap size={13} />
                  <span>
                    {customWirePayload !== signedToolParams
                      ? 'Restore Signed Wire Payload'
                      : 'Simulate MITM Wire Payload Tamper'}
                  </span>
                </button>
              </div>
            </div>

            <div className="pillars-grid">
              {/* Pillar 1: Agent Identity */}
              <div
                className={`pillar-card ${
                  verificationChecks.checkIdentity ? 'pillar-ok' : 'pillar-fail'
                }`}
                onClick={() => setCurrentStep(2)}
              >
                <div className="pillar-top">
                  <span className="pillar-index">PILLAR 1</span>
                  <span
                    className={`pillar-status ${
                      verificationChecks.checkIdentity ? 'ok' : 'fail'
                    }`}
                  >
                    {verificationChecks.checkIdentity ? 'VERIFIED SVID' : 'FORGED KEY'}
                  </span>
                </div>
                <div className="pillar-title-row">
                  <Key size={15} className="icon-cyan" />
                  <h4>Agent Identity (Passport)</h4>
                </div>
                <p className="pillar-explain">
                  Binds request to verified public key & workload identity so rogue pods cannot impersonate the agent.
                </p>
                <div className="pillar-kv">
                  <span>SPIFFE ID:</span>
                  <code>{currentScenario.agentIdentity.spiffeId}</code>
                </div>
                <div className="pillar-kv">
                  <span>Algorithm:</span>
                  <code>{currentScenario.agentIdentity.keyAlgorithm}</code>
                </div>
                <div className="pillar-kv">
                  <span>Cloud KMS Key:</span>
                  <code>{currentScenario.agentIdentity.kmsKeyUri}</code>
                </div>
              </div>

              {/* Pillar 2: Input/Output Digests */}
              <div
                className={`pillar-card ${
                  verificationChecks.checkInputDigest ? 'pillar-ok' : 'pillar-fail'
                }`}
                onClick={() => setCurrentStep(3)}
              >
                <div className="pillar-top">
                  <span className="pillar-index">PILLAR 2</span>
                  <span
                    className={`pillar-status ${
                      verificationChecks.checkInputDigest ? 'ok' : 'fail'
                    }`}
                  >
                    {verificationChecks.checkInputDigest ? 'SHA-256 MATCH' : 'DIGEST MISMATCH'}
                  </span>
                </div>
                <div className="pillar-title-row">
                  <Hash size={15} className="icon-cyan" />
                  <h4>Input / Output Digests</h4>
                </div>
                <p className="pillar-explain">
                  Cryptographic SHA-256 hashes of prompt context, tool parameters, and response payloads.
                </p>
                <div className="pillar-kv">
                  <span>Prompt SHA-256:</span>
                  <code>{promptDigest.slice(0, 24)}...</code>
                </div>
                <div className="pillar-kv">
                  <span>Signed Tool Params SHA-256:</span>
                  <code className="text-emerald">{signedInputDigest.slice(0, 24)}...</code>
                </div>
                <div className="pillar-kv">
                  <span>Wire Payload SHA-256 (Live):</span>
                  <code
                    className={
                      verificationChecks.checkInputDigest ? 'text-emerald' : 'text-rose'
                    }
                  >
                    {liveWireDigest.slice(0, 24)}...
                  </code>
                </div>
              </div>

              {/* Pillar 3: Policy Decision Proof */}
              <div
                className={`pillar-card ${
                  verificationChecks.checkPolicy ? 'pillar-ok' : 'pillar-fail'
                }`}
                onClick={() => setCurrentStep(4)}
              >
                <div className="pillar-top">
                  <span className="pillar-index">PILLAR 3</span>
                  <span
                    className={`pillar-status ${
                      verificationChecks.checkPolicy ? 'ok' : 'fail'
                    }`}
                  >
                    VERDICT: {currentScenario.policyProof.verdict}
                  </span>
                </div>
                <div className="pillar-title-row">
                  <Lock size={15} className="icon-cyan" />
                  <h4>Policy Decision Proof</h4>
                </div>
                <p className="pillar-explain">
                  Deterministic policy gateway evaluates AST & bounds outside the LLM and signs an ALLOW/DENY verdict.
                </p>
                <div className="pillar-kv">
                  <span>Policy Engine:</span>
                  <code>{currentScenario.policyProof.engine}</code>
                </div>
                <div className="pillar-kv">
                  <span>Rule ID:</span>
                  <code>{currentScenario.policyProof.policyId}</code>
                </div>
                <div className="pillar-invariants">
                  {currentScenario.policyProof.invariantsChecked.map((inv, idx) => (
                    <div key={idx} className="invariant-line">
                      • {inv}
                    </div>
                  ))}
                </div>
              </div>

              {/* Pillar 4: Liveness Proofs */}
              <div
                className={`pillar-card ${
                  verificationChecks.checkLiveness ? 'pillar-ok' : 'pillar-fail'
                }`}
                onClick={() => setCurrentStep(5)}
              >
                <div className="pillar-top">
                  <span className="pillar-index">PILLAR 4</span>
                  <span
                    className={`pillar-status ${
                      verificationChecks.checkLiveness ? 'ok' : 'fail'
                    }`}
                  >
                    {verificationChecks.checkLiveness ? 'FRESH NONCE' : 'REPLAY DETECTED'}
                  </span>
                </div>
                <div className="pillar-title-row">
                  <Clock size={15} className="icon-cyan" />
                  <h4>Liveness Proofs (RFC 9334)</h4>
                </div>
                <p className="pillar-explain">
                  RATS-compliant freshness nonces & timestamps prevent replay of captured receipts.
                </p>
                <div className="pillar-kv">
                  <span>RFC 9334 RATS Nonce:</span>
                  <code>{currentScenario.livenessProof.ratsNonce}</code>
                </div>
                <div className="pillar-kv">
                  <span>Issued / Expires:</span>
                  <code>
                    {currentScenario.livenessProof.issuedAt.slice(11, 23)} &rarr;{' '}
                    {currentScenario.livenessProof.expiresAt.slice(11, 23)}
                  </code>
                </div>
                <div className="pillar-kv">
                  <span>Observed Age vs TTL:</span>
                  <code
                    className={
                      verificationChecks.checkLiveness ? 'text-emerald' : 'text-rose'
                    }
                  >
                    {currentScenario.livenessProof.clockSkewMs}ms / 15,000ms max TTL
                  </code>
                </div>
              </div>
            </div>

            {/* Live Wire Payload Editor to test real-time SHA-256 Digest & Merkle Cascade */}
            <div className="live-tamper-editor">
              <div className="editor-header">
                <div className="editor-title">
                  <Terminal size={14} className="icon-cyan" />
                  <span>
                    Live Wire Payload Inspector (Edit JSON below to test real-time SHA-256 & Merkle Root verification)
                  </span>
                </div>
                <span
                  className={`digest-match-badge ${
                    verificationChecks.checkInputDigest ? 'match' : 'mismatch'
                  }`}
                >
                  {verificationChecks.checkInputDigest
                    ? '✓ Wire SHA-256 Matches Signed Receipt Digest'
                    : '✗ Wire SHA-256 Mismatch! Tampering Detected'}
                </span>
              </div>
              <textarea
                className="wire-textarea"
                value={customWirePayload}
                onChange={(e) => {
                  setCustomWirePayload(e.target.value);
                  setIsWireTamperedManually(e.target.value !== signedToolParams);
                }}
                rows={2}
                aria-label="Editable Wire Payload JSON"
              />
            </div>
          </div>

          {/* 3. HASH-CHAINED / MERKLE ARCHITECTURE VISUALIZER (IETF SCITT) */}
          <div className="viz-card">
            <div className="viz-card-header">
              <div className="viz-title-wrap">
                <GitMerge size={16} className="icon-cyan" />
                <h3>
                  Hash-Chained & Distributed Merkle Tree Architecture (IETF SCITT Transparency Log)
                </h3>
              </div>
              <span className="viz-step-indicator">
                Click any Receipt Leaf (#0–#3) to highlight its Merkle Inclusion Proof path
              </span>
            </div>

            <div className="merkle-explainer-bar">
              <p>
                Every receipt is cryptographically chained to its predecessor (<code>prev_receipt_hash</code>) AND anchored as a leaf in a binary <strong>Merkle Tree</strong>. To verify Receipt #{selectedMerkleLeafIdx}, the downstream verifier only needs the <strong>Signed Merkle Root</strong> and <strong>2 Witness Hashes</strong> (highlighted in amber) to recompute the root in <span className="mono-inline">O(log N)</span> time.
              </p>
            </div>

            {/* Interactive SVG Merkle Tree + Hash Chain */}
            <div className="merkle-svg-container">
              <svg
                viewBox="0 0 920 285"
                className="merkle-svg"
                role="img"
                aria-label="Interactive SCITT Merkle Tree and Hash Chain"
              >
                {/* Lines from Root to Level 1 Branches */}
                <line
                  x1="460"
                  y1="62"
                  x2="255"
                  y2="112"
                  stroke={merkleState.branches[0].isTampered ? '#f43f5e' : '#38bdf8'}
                  strokeWidth="2.4"
                />
                <line
                  x1="460"
                  y1="62"
                  x2="665"
                  y2="112"
                  stroke={merkleState.branches[1].isTampered ? '#f43f5e' : '#38bdf8'}
                  strokeWidth="2.4"
                />

                {/* Lines from Branches to 4 Leaves */}
                {[0, 1, 2, 3].map((leafIdx) => {
                  const branchX = leafIdx < 2 ? 255 : 665;
                  const leafX = 115 + leafIdx * 230;
                  const leaf = merkleState.leaves[leafIdx];
                  const isSelectedPath =
                    leafIdx === selectedMerkleLeafIdx || leafIdx === siblingLeafIdx;
                  return (
                    <line
                      key={leafIdx}
                      x1={branchX}
                      y1="164"
                      x2={leafX}
                      y2="205"
                      stroke={
                        leaf.isTampered
                          ? '#f43f5e'
                          : isSelectedPath
                          ? '#fbbf24'
                          : '#475569'
                      }
                      strokeWidth={isSelectedPath || leaf.isTampered ? '2.5' : '1.6'}
                    />
                  );
                })}

                {/* Horizontal Hash-Chain Links (prev_receipt_hash) between Leaves */}
                {[0, 1, 2].map((idx) => {
                  const x1 = 115 + idx * 230 + 96;
                  const x2 = 115 + (idx + 1) * 230 - 96;
                  const nextLeafTampered = merkleState.leaves[idx + 1].isTampered;
                  return (
                    <g key={`chain-${idx}`}>
                      <line
                        x1={x1}
                        y1="242"
                        x2={x2}
                        y2="242"
                        stroke={nextLeafTampered ? '#f43f5e' : '#10b981'}
                        strokeWidth="2"
                        strokeDasharray="4 2"
                      />
                      <polygon
                        points={`${x2 - 5},238 ${x2},242 ${x2 - 5},246`}
                        fill={nextLeafTampered ? '#f43f5e' : '#10b981'}
                      />
                      <text
                        x={(x1 + x2) / 2 - 16}
                        y="234"
                        fill="#94a3b8"
                        fontSize="8.5"
                        fontFamily="JetBrains Mono"
                      >
                        prev_hash
                      </text>
                    </g>
                  );
                })}

                {/* MERKLE ROOT NODE */}
                <g>
                  <rect
                    x="275"
                    y="10"
                    width="370"
                    height="52"
                    rx="10"
                    fill={merkleState.rootValid ? '#064e3b' : '#4c0519'}
                    stroke={merkleState.rootValid ? '#10b981' : '#f43f5e'}
                    strokeWidth="2.2"
                  />
                  <text
                    x="292"
                    y="30"
                    fill="#ffffff"
                    fontSize="11.5"
                    fontWeight="700"
                  >
                    {merkleState.rootValid
                      ? '🌳 SIGNED SCITT MERKLE ROOT H(0123) — VERIFIED'
                      : '🚨 SCITT MERKLE ROOT MISMATCH — LEDGER TAMPERED!'}
                  </text>
                  <text
                    x="292"
                    y="48"
                    fill={merkleState.rootValid ? '#6ee7b7' : '#fda4af'}
                    fontSize="10"
                    fontFamily="JetBrains Mono"
                  >
                    {merkleState.actualRoot.slice(0, 44)}...
                  </text>
                </g>

                {/* INTERMEDIATE BRANCH NODES H(01) and H(23) */}
                {merkleState.branches.map((b, bIdx) => {
                  const centerX = bIdx === 0 ? 255 : 665;
                  const isWitnessBranch = bIdx === cousinBranchIdx;
                  const isComputedBranch = bIdx === parentBranchIdx;
                  return (
                    <g key={b.label}>
                      <rect
                        x={centerX - 135}
                        y="112"
                        width="270"
                        height="52"
                        rx="9"
                        fill={
                          b.isTampered
                            ? '#3b0a14'
                            : isWitnessBranch
                            ? '#3b2506'
                            : '#111827'
                        }
                        stroke={
                          b.isTampered
                            ? '#f43f5e'
                            : isWitnessBranch
                            ? '#fbbf24'
                            : isComputedBranch
                            ? '#38bdf8'
                            : '#334155'
                        }
                        strokeWidth="2"
                      />
                      <text
                        x={centerX - 120}
                        y="132"
                        fill="#f8fafc"
                        fontSize="11"
                        fontWeight="700"
                      >
                        {b.label}{' '}
                        {isWitnessBranch
                          ? '• [MERKLE PROOF WITNESS #2]'
                          : '• [COMPUTED INTERMEDIATE]'}
                      </text>
                      <text
                        x={centerX - 120}
                        y="150"
                        fill={
                          b.isTampered
                            ? '#fda4af'
                            : isWitnessBranch
                            ? '#fcd34d'
                            : '#7dd3fc'
                        }
                        fontSize="9.8"
                        fontFamily="JetBrains Mono"
                      >
                        SHA256: {b.actualHash.slice(0, 28)}...
                      </text>
                    </g>
                  );
                })}

                {/* 4 RECEIPT LEAF NODES */}
                {merkleState.leaves.map((leaf, idx) => {
                  const centerX = 115 + idx * 230;
                  const isSelected = idx === selectedMerkleLeafIdx;
                  const isSiblingWitness = idx === siblingLeafIdx;
                  return (
                    <g
                      key={leaf.receiptId}
                      className="svg-node"
                      onClick={() => setSelectedMerkleLeafIdx(idx)}
                    >
                      <rect
                        x={centerX - 96}
                        y="205"
                        width="192"
                        height="70"
                        rx="9"
                        fill={
                          leaf.isTampered
                            ? '#3b0a14'
                            : isSelected
                            ? '#0c2d48'
                            : isSiblingWitness
                            ? '#3b2506'
                            : '#0f172a'
                        }
                        stroke={
                          leaf.isTampered
                            ? '#f43f5e'
                            : isSelected
                            ? '#38bdf8'
                            : isSiblingWitness
                            ? '#fbbf24'
                            : '#334155'
                        }
                        strokeWidth={isSelected || isSiblingWitness || leaf.isTampered ? '2.2' : '1.4'}
                      />
                      <text
                        x={centerX - 84}
                        y="224"
                        fill="#ffffff"
                        fontSize="10.5"
                        fontWeight="700"
                      >
                        Leaf #{idx}: {leaf.receiptId}
                      </text>
                      <text
                        x={centerX - 84}
                        y="240"
                        fill={
                          leaf.isTampered
                            ? '#fda4af'
                            : isSelected
                            ? '#38bdf8'
                            : isSiblingWitness
                            ? '#fbbf24'
                            : '#94a3b8'
                        }
                        fontSize="9"
                        fontWeight="600"
                      >
                        {leaf.isTampered
                          ? '✗ HASH TAMPERED!'
                          : isSelected
                          ? '★ TARGET LEAF TO VERIFY'
                          : isSiblingWitness
                          ? '⚡ WITNESS SIBLING #1'
                          : leaf.tool}
                      </text>
                      <text
                        x={centerX - 84}
                        y="258"
                        fill="#cbd5e1"
                        fontSize="9"
                        fontFamily="JetBrains Mono"
                      >
                        H({idx}): {leaf.actualLeafHash.slice(0, 18)}...
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Interactive Receipt Chain Tamper Controls */}
            <div className="merkle-controls-row">
              <div className="merkle-proof-equation">
                <span className="eq-label">Inclusion Proof for Leaf #{selectedMerkleLeafIdx}:</span>
                <code>
                  Root = SHA256( {parentBranchIdx === 0 ? `SHA256(L${selectedMerkleLeafIdx === 0 ? '0 || Witness_L1' : 'Witness_L0 || L1'}) || Witness_H(23)` : `Witness_H(01) || SHA256(${selectedMerkleLeafIdx === 2 ? 'L2 || Witness_L3' : 'Witness_L2 || L3'})`} )
                </code>
              </div>

              <div className="tamper-buttons-wrap">
                {[0, 1, 2].map((idx) => {
                  const isTampered = historicalReceipts[idx].tamperedPayloadSummary !== null;
                  return (
                    <button
                      key={idx}
                      type="button"
                      className={`mini-tamper-btn ${isTampered ? 'active' : ''}`}
                      onClick={() => toggleTamperHistoricalReceipt(idx)}
                    >
                      {isTampered ? `Restore Leaf #${idx}` : `Tamper Leaf #${idx}`}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* 4. INDEPENDENT DOWNSTREAM VERIFICATION MATRIX */}
          <div className="viz-card">
            <div className="viz-card-header">
              <div className="viz-title-wrap">
                <Server size={16} className="icon-cyan" />
                <h3>
                  Independent Verifiability: {currentTarget.name} Mathematical Proof Gate
                </h3>
              </div>
              <span className="target-endpoint-pill">{currentTarget.endpoint}</span>
            </div>

            <div className="verifier-table-wrap">
              <table className="verifier-table">
                <thead>
                  <tr>
                    <th>Verification Gate</th>
                    <th>Cryptographic Primitive / Standard</th>
                    <th>Mathematical Equation Evaluated by Verifier</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <strong>1. Agent Identity Binding</strong>
                    </td>
                    <td>
                      <code>Ed25519 + SPIFFE SVID</code>
                    </td>
                    <td>
                      <code>Verify_Ed25519(KMS_PubKey, Receipt_Digest, Sig) == true</code>
                    </td>
                    <td>
                      <span
                        className={`table-badge ${
                          verificationChecks.checkIdentity ? 'pass' : 'fail'
                        }`}
                      >
                        {verificationChecks.checkIdentity ? 'PASS' : 'FAIL (UNTRUSTED KEY)'}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <strong>2. I/O Payload Digest</strong>
                    </td>
                    <td>
                      <code>SHA-256 (FIPS 180-4)</code>
                    </td>
                    <td>
                      <code>
                        SHA256(Wire_Payload) [{liveWireDigest.slice(0, 8)}...] == Receipt.input_digest [{signedInputDigest.slice(0, 8)}...]
                      </code>
                    </td>
                    <td>
                      <span
                        className={`table-badge ${
                          verificationChecks.checkInputDigest ? 'pass' : 'fail'
                        }`}
                      >
                        {verificationChecks.checkInputDigest ? 'PASS' : 'FAIL (HASH MISMATCH)'}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <strong>3. Deterministic Policy Proof</strong>
                    </td>
                    <td>
                      <code>Cedar / OPA Signed Verdict</code>
                    </td>
                    <td>
                      <code>
                        Receipt.verdict == &quot;ALLOW&quot; &amp;&amp; Verify_Sig(Policy_PK, Verdict)
                      </code>
                    </td>
                    <td>
                      <span
                        className={`table-badge ${
                          verificationChecks.checkPolicy ? 'pass' : 'fail'
                        }`}
                      >
                        {verificationChecks.checkPolicy
                          ? 'PASS (ALLOW)'
                          : `FAIL (${currentScenario.policyProof.verdict})`}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <strong>4. Liveness & Anti-Replay</strong>
                    </td>
                    <td>
                      <code>RFC 9334 RATS Freshness Nonce</code>
                    </td>
                    <td>
                      <code>
                        Now - IssuedAt ({currentScenario.livenessProof.clockSkewMs}ms) &lt;= 15000ms &amp;&amp; !Spent(Nonce)
                      </code>
                    </td>
                    <td>
                      <span
                        className={`table-badge ${
                          verificationChecks.checkLiveness ? 'pass' : 'fail'
                        }`}
                      >
                        {verificationChecks.checkLiveness ? 'PASS (FRESH)' : 'FAIL (STALE/REPLAY)'}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <strong>5. Transparency Log Inclusion</strong>
                    </td>
                    <td>
                      <code>IETF SCITT Binary Merkle Tree</code>
                    </td>
                    <td>
                      <code>
                        MerkleRoot(Leaf_3, Witness_Siblings) [{merkleState.actualRoot.slice(0, 8)}...] == Signed_Root [{merkleState.expectedRoot.slice(0, 8)}...]
                      </code>
                    </td>
                    <td>
                      <span
                        className={`table-badge ${
                          verificationChecks.checkMerkle ? 'pass' : 'fail'
                        }`}
                      >
                        {verificationChecks.checkMerkle ? 'PASS (INCLUDED)' : 'FAIL (ROOT INVALID)'}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* RIGHT RESIZE SPLITTER */}
        <div
          className="splitter-bar"
          onMouseDown={() => {
            isDraggingRight.current = true;
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
          }}
          title="Drag to resize right inspector panel"
        />

        {/* RIGHT PANEL: LIVE CRYPTOGRAPHIC RECEIPT JSON & MERKLE PROOF INSPECTOR */}
        <aside className="panel right-panel" style={{ width: `${rightWidth}px` }}>
          <div className="panel-header">
            <div className="panel-title-group">
              <Terminal size={16} className="icon-cyan" />
              <h2>Cryptographic Inspector</h2>
            </div>
            <span
              className={`inspector-status-tag ${
                verificationChecks.allPassed ? 'valid' : 'invalid'
              }`}
            >
              {verificationChecks.allPassed ? 'PROOF VALID' : 'PROOF REJECTED'}
            </span>
          </div>

          {/* Inspector Tabs */}
          <div className="inspector-tabs">
            <button
              type="button"
              className={`insp-tab ${activeRightTab === 'receipt_json' ? 'active' : ''}`}
              onClick={() => setActiveRightTab('receipt_json')}
            >
              Receipt JSON
            </button>
            <button
              type="button"
              className={`insp-tab ${activeRightTab === 'merkle_proof' ? 'active' : ''}`}
              onClick={() => setActiveRightTab('merkle_proof')}
            >
              Merkle Math
            </button>
            <button
              type="button"
              className={`insp-tab ${activeRightTab === 'wire_headers' ? 'active' : ''}`}
              onClick={() => setActiveRightTab('wire_headers')}
            >
              Wire Headers
            </button>
            <button
              type="button"
              className={`insp-tab ${activeRightTab === 'spec_notes' ? 'active' : ''}`}
              onClick={() => setActiveRightTab('spec_notes')}
            >
              Spec Notes
            </button>
          </div>

          <div className="inspector-content">
            {activeRightTab === 'receipt_json' && (
              <div className="code-panel-wrap">
                <div className="code-toolbar">
                  <span>SCITT Attestation Receipt Envelope (COSE_Sign1 JSON)</span>
                  <button
                    type="button"
                    className="copy-btn"
                    onClick={() => handleCopy('receipt', fullReceiptJson)}
                  >
                    {copiedKey === 'receipt' ? <Check size={13} /> : <Copy size={13} />}
                    <span>{copiedKey === 'receipt' ? 'Copied' : 'Copy JSON'}</span>
                  </button>
                </div>
                <pre className="json-code-block">{fullReceiptJson}</pre>
              </div>
            )}

            {activeRightTab === 'merkle_proof' && (
              <div className="merkle-math-panel">
                <div className="math-card">
                  <h4>1. Selected Leaf Hash (Receipt #{selectedMerkleLeafIdx})</h4>
                  <p className="math-sub">
                    Canonical hash over receipt ID, timestamp, SPIFFE SVID, tool, verdict, RFC 9334 nonce, payload, and <code>prev_receipt_hash</code>:
                  </p>
                  <div className="hash-box">
                    <span className="hash-label">prev_receipt_hash:</span>
                    <code>{activeMerkleLeaf.prevActualHash}</code>
                  </div>
                  <div className="hash-box">
                    <span className="hash-label">Expected Leaf SHA-256:</span>
                    <code className="text-emerald">{activeMerkleLeaf.expectedLeafHash}</code>
                  </div>
                  <div className="hash-box">
                    <span className="hash-label">Actual Leaf SHA-256:</span>
                    <code
                      className={
                        activeMerkleLeaf.isTampered ? 'text-rose' : 'text-emerald'
                      }
                    >
                      {activeMerkleLeaf.actualLeafHash}
                    </code>
                  </div>
                </div>

                <div className="math-card">
                  <h4>2. Witness #1: Sibling Leaf (#{siblingLeafIdx})</h4>
                  <p className="math-sub">
                    Provided in the SCITT inclusion proof so the verifier can compute parent branch{' '}
                    <code>{merkleState.branches[parentBranchIdx].label}</code>:
                  </p>
                  <div className="hash-box">
                    <span className="hash-label">Sibling Leaf #{siblingLeafIdx} SHA-256:</span>
                    <code className="text-amber">{siblingLeaf.actualLeafHash}</code>
                  </div>
                  <div className="hash-box">
                    <span className="hash-label">
                      Computed {merkleState.branches[parentBranchIdx].label}:
                    </span>
                    <code className="text-cyan">
                      {merkleState.branches[parentBranchIdx].actualHash}
                    </code>
                  </div>
                </div>

                <div className="math-card">
                  <h4>
                    3. Witness #2: Cousin Branch ({merkleState.branches[cousinBranchIdx].label}) &rarr; Root
                  </h4>
                  <div className="hash-box">
                    <span className="hash-label">
                      Witness {merkleState.branches[cousinBranchIdx].label}:
                    </span>
                    <code className="text-amber">
                      {merkleState.branches[cousinBranchIdx].actualHash}
                    </code>
                  </div>
                  <div className="hash-box">
                    <span className="hash-label">Signed SCITT Merkle Root:</span>
                    <code className="text-emerald">{merkleState.expectedRoot}</code>
                  </div>
                  <div className="hash-box">
                    <span className="hash-label">Verifier Recomputed Root:</span>
                    <code
                      className={merkleState.rootValid ? 'text-emerald' : 'text-rose'}
                    >
                      {merkleState.actualRoot}
                    </code>
                  </div>
                </div>
              </div>
            )}

            {activeRightTab === 'wire_headers' && (
              <div className="code-panel-wrap">
                <div className="code-toolbar">
                  <span>Downstream Transport Headers & Verifier Response</span>
                  <button
                    type="button"
                    className="copy-btn"
                    onClick={() =>
                      handleCopy('headers', currentScenario.responsePayload)
                    }
                  >
                    {copiedKey === 'headers' ? <Check size={13} /> : <Copy size={13} />}
                    <span>Copy</span>
                  </button>
                </div>
                <pre className="json-code-block">{`POST ${currentTarget.endpoint}
Host: ${currentTarget.id}.us-central1.example.com
X-GCP-Project-ID: acme-adk-prod
X-ADK-Agent-SPIFFE: ${currentScenario.agentIdentity.spiffeId}
X-ADK-Key-URI: ${currentScenario.agentIdentity.kmsKeyUri}
X-ADK-Input-SHA256: ${signedInputDigest}
X-ADK-Policy-Verdict: ${currentScenario.policyProof.verdict} (${currentScenario.policyProof.policyId})
X-RATS-Freshness-Nonce: ${currentScenario.livenessProof.ratsNonce}
X-SCITT-Merkle-Root: ${merkleState.expectedRoot}
X-SCITT-Witness-0: ${siblingLeaf.actualLeafHash}
X-SCITT-Witness-1: ${merkleState.branches[cousinBranchIdx].actualHash}

--- WIRE PAYLOAD RECEIVED BY VERIFIER ---
${customWirePayload}

--- DOWNSTREAM VERIFIER RESPONSE ---
${JSON.stringify(JSON.parse(currentScenario.responsePayload), null, 2)}`}</pre>
              </div>
            )}

            {activeRightTab === 'spec_notes' && (
              <div className="spec-notes-panel">
                <div className="spec-block">
                  <h4>Why Decouple Reasoning from Execution?</h4>
                  <p>
                    LLMs operate as probabilistic next-token generators where control instructions and untrusted data occupy the same context window. Giving an LLM direct execution authority (such as an unguarded database connection or Kubernetes cluster-admin role) means any prompt injection or hallucination immediately translates into unauthorized state mutation.
                  </p>
                </div>

                <div className="spec-block">
                  <h4>Cryptographic Standards Used</h4>
                  <table className="mini-spec-table">
                    <thead>
                      <tr>
                        <th>Component</th>
                        <th>Standard / Primitive</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Agent Identity</td>
                        <td>SPIFFE/SVID + Ed25519 (RFC 8032) in Cloud KMS</td>
                      </tr>
                      <tr>
                        <td>I/O Digests</td>
                        <td>Canonical JSON SHA-256 (FIPS 180-4)</td>
                      </tr>
                      <tr>
                        <td>Policy Engine</td>
                        <td>Deterministic Cedar / OPA Signed Verdict</td>
                      </tr>
                      <tr>
                        <td>Liveness Proof</td>
                        <td>RFC 9334 RATS Challenge Nonce + Epoch TTL</td>
                      </tr>
                      <tr>
                        <td>Transparency Log</td>
                        <td>IETF SCITT + RFC 9162 Binary Merkle Tree</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </aside>
      </main>
    </div>
  );
}
