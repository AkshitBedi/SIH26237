/**
 * SIH Problem Statement 26237: Cryptographic Attribution & Provenance Console.
 * Vanilla JavaScript client-side controller.
 * Interfaces with real backend endpoints.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const btnEncrypt = document.getElementById("btn-encrypt");
  const btnDecrypt = document.getElementById("btn-decrypt");
  const btnTrace = document.getElementById("btn-trace");
  const btnApplyLeak = document.getElementById("btn-apply-leak");
  const btnFullDemo = document.getElementById("btn-full-demo");
  const btnReset = document.getElementById("btn-reset");

  const btnViewEvidence = document.getElementById("btn-view-evidence");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const evidenceModal = document.getElementById("evidence-modal");
  const modalContent = document.getElementById("modal-evidence-content");
  const linkDownloadEvidence = document.getElementById("link-download-evidence");
  const btnModalDownload = document.getElementById("btn-modal-download");

  let currentEvidenceBundle = null;
  let currentEvidenceReport = "";

  // Pipeline Stage Helpers
  function setPipelineStep(stepId, state) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.classList.remove("active", "completed");
    if (state === "active") el.classList.add("active");
    if (state === "completed") el.classList.add("completed");
  }

  function resetPipeline() {
    const steps = [
      "p-encrypt", "p-distribute", "p-authenticate", "p-commit",
      "p-watermark", "p-release", "p-leak", "p-trace", "p-attribute"
    ];
    steps.forEach(s => {
      const el = document.getElementById(s);
      if (el) el.classList.remove("active", "completed");
    });
    document.getElementById("pipeline-status-chip").textContent = "SYSTEM READY";
    document.getElementById("pipeline-status-chip").className = "chip chip-info";
  }

  // Refresh status on load
  function fetchStatus() {
    fetch("/api/status")
      .then(res => res.json())
      .then(data => {
        if (data.has_decrypted) {
          const decImg = document.getElementById("dec-img-preview");
          if (decImg) decImg.src = `/api/image/decrypted?t=${Date.now()}`;
        }
        if (data.has_leak) {
          const leakImg = document.getElementById("leak-img-preview");
          if (leakImg) leakImg.src = `/api/image/leaked?t=${Date.now()}`;
        }
      })
      .catch(err => console.error("Status fetch error:", err));
  }

  fetchStatus();

  // RESET / INITIALIZE
  btnReset.addEventListener("click", () => {
    btnReset.disabled = true;
    fetch("/api/setup", { method: "POST" })
      .then(res => res.json())
      .then(data => {
        btnReset.disabled = false;
        resetPipeline();
        document.getElementById("encrypt-result").style.display = "none";
        document.getElementById("decrypt-result").style.display = "none";
        document.getElementById("decrypt-error").style.display = "none";
        document.getElementById("decrypt-flow").style.display = "none";
        document.getElementById("trace-result-success").style.display = "none";
        document.getElementById("trace-result-failed").style.display = "none";
        document.getElementById("trace-flow").style.display = "none";
        fetchStatus();
        alert("Demo environment, PQC keystores, and canvas successfully reset.");
      })
      .catch(err => {
        btnReset.disabled = false;
        alert("Reset failed: " + err.message);
      });
  });

  // STEP 1: ENCRYPT & DISTRIBUTE
  btnEncrypt.addEventListener("click", () => {
    const recipients = [];
    if (document.getElementById("rec-001").checked) recipients.push("REC-001");
    if (document.getElementById("rec-002").checked) recipients.push("REC-002");
    if (document.getElementById("rec-047").checked) recipients.push("REC-047");

    if (recipients.length === 0) {
      alert("Please select at least one recipient.");
      return;
    }

    btnEncrypt.disabled = true;
    btnEncrypt.innerHTML = "<span>⚙️</span> Encrypting with ML-KEM-768...";
    setPipelineStep("p-encrypt", "active");

    fetch("/api/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recipients: recipients })
    })
      .then(res => res.json())
      .then(data => {
        btnEncrypt.disabled = false;
        btnEncrypt.innerHTML = "<span>🛡️</span> ENCRYPT & DISTRIBUTE";

        if (!data.success) {
          alert("Encryption failed: " + data.error);
          setPipelineStep("p-encrypt", "");
          return;
        }

        // Update UI
        setPipelineStep("p-encrypt", "completed");
        setPipelineStep("p-distribute", "completed");

        document.getElementById("enc-doc-hash").textContent = data.document_hash;
        document.getElementById("enc-recipients").textContent = data.recipients.join(", ");
        document.getElementById("enc-pkg-path").textContent = data.package_path;
        document.getElementById("encrypt-result").style.display = "block";
      })
      .catch(err => {
        btnEncrypt.disabled = false;
        btnEncrypt.innerHTML = "<span>🛡️</span> ENCRYPT & DISTRIBUTE";
        alert("Encryption error: " + err.message);
      });
  });

  // STEP 2: DECRYPT & COMMIT (COMMIT-BEFORE-RELEASE)
  btnDecrypt.addEventListener("click", async () => {
    const recipientId = document.getElementById("decrypt-recipient-select").value;
    const faultyValStr = document.getElementById("faulty-validator-select").value;
    const faultyValidators = faultyValStr ? faultyValStr.split(",") : [];

    btnDecrypt.disabled = true;
    document.getElementById("decrypt-result").style.display = "none";
    document.getElementById("decrypt-error").style.display = "none";

    const flowBox = document.getElementById("decrypt-flow");
    flowBox.style.display = "block";

    const flowSteps = [
      { id: "df-auth", text: "AUTHENTICATING RECIPIENT (ML-DSA-65 CHALLENGE)", delay: 350 },
      { id: "df-sess", text: "CREATING SESSION & WATERMARK ID", delay: 300 },
      { id: "df-sign", text: "SIGNING PROVENANCE (ML-DSA-65 PRIVATE KEY)", delay: 350 },
      { id: "df-ledger", text: "COMMITTING TO OFFLINE PERMISSIONED LEDGER", delay: 400 },
      { id: "df-quorum", text: "4-OF-5 VALIDATOR QUORUM ATTESTATION", delay: 450 },
      { id: "df-watermark", text: "EMBEDDING INVISIBLE FORENSIC WATERMARK", delay: 350 },
      { id: "df-release", text: "RELEASE AUTHORIZED", delay: 200 }
    ];

    // Reset flow items
    flowSteps.forEach(s => {
      const el = document.getElementById(s.id);
      el.className = "flow-step";
    });

    setPipelineStep("p-authenticate", "active");

    // Animate flow sequentially
    for (let i = 0; i < 4; i++) {
      const step = flowSteps[i];
      const el = document.getElementById(step.id);
      el.className = "flow-step active";
      await new Promise(r => setTimeout(r, step.delay));
      el.className = "flow-step done";
    }

    setPipelineStep("p-authenticate", "completed");
    setPipelineStep("p-commit", "active");

    fetch("/api/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient_id: recipientId,
        faulty_validators: faultyValidators
      })
    })
      .then(res => res.json())
      .then(async data => {
        btnDecrypt.disabled = false;

        if (!data.success) {
          // Invariant violation or quorum error
          setPipelineStep("p-commit", "");
          document.getElementById("dec-error-text").textContent = data.error;
          document.getElementById("decrypt-error").style.display = "block";
          document.getElementById("df-quorum").className = "flow-step active";
          document.getElementById("df-quorum").textContent = "5. QUORUM FAILURE: COMMIT HALTED";
          document.getElementById("df-release").textContent = "7. RELEASE ABORTED (NO PLAINTEXT RELEASED)";
          return;
        }

        // Complete remaining flow steps
        for (let i = 4; i < flowSteps.length; i++) {
          const step = flowSteps[i];
          const el = document.getElementById(step.id);
          el.className = "flow-step active";
          await new Promise(r => setTimeout(r, step.delay));
          el.className = "flow-step done";
        }

        setPipelineStep("p-commit", "completed");
        setPipelineStep("p-watermark", "completed");
        setPipelineStep("p-release", "completed");

        // Display results
        document.getElementById("dec-rec").textContent = data.recipient_id;
        document.getElementById("dec-sess").textContent = data.session_id;
        document.getElementById("dec-wmid").textContent = data.watermark_id;
        document.getElementById("dec-block").textContent = "#" + data.block_height;
        document.getElementById("dec-quorum").textContent = data.quorum_count + " ✓";

        const decImg = document.getElementById("dec-img-preview");
        decImg.src = data.image_url;

        const leakImg = document.getElementById("leak-img-preview");
        leakImg.src = data.leak_url;

        document.getElementById("decrypt-result").style.display = "block";
      })
      .catch(err => {
        btnDecrypt.disabled = false;
        alert("Decryption exception: " + err.message);
      });
  });

  // STEP 3: SIMULATE LEAK ATTACK
  btnApplyLeak.addEventListener("click", () => {
    const attack = document.getElementById("leak-attack-select").value;
    const recipientId = document.getElementById("decrypt-recipient-select").value;

    btnApplyLeak.disabled = true;
    setPipelineStep("p-leak", "active");

    fetch("/api/simulate-leak", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack: attack, recipient_id: recipientId })
    })
      .then(res => res.json())
      .then(data => {
        btnApplyLeak.disabled = false;
        if (!data.success) {
          alert("Simulation failed: " + data.error);
          return;
        }
        setPipelineStep("p-leak", "completed");
        const leakImg = document.getElementById("leak-img-preview");
        leakImg.src = data.leak_url;
        document.getElementById("leak-caption").textContent = `Simulated Leak (${attack.toUpperCase()} | ${data.dimensions})`;
      })
      .catch(err => {
        btnApplyLeak.disabled = false;
        alert("Leak simulation error: " + err.message);
      });
  });

  // STEP 4: FORENSIC ATTRIBUTION (THE MAIN WOW MOMENT)
  btnTrace.addEventListener("click", async () => {
    btnTrace.disabled = true;
    document.getElementById("trace-result-success").style.display = "none";
    document.getElementById("trace-result-failed").style.display = "none";

    const flowBox = document.getElementById("trace-flow");
    flowBox.style.display = "block";

    const traceSteps = [
      { id: "tf-extract", delay: 350 },
      { id: "tf-ecc", delay: 250 },
      { id: "tf-lookup", delay: 350 },
      { id: "tf-dsa", delay: 300 },
      { id: "tf-merkle", delay: 300 },
      { id: "tf-quorum", delay: 300 },
      { id: "tf-attr", delay: 200 }
    ];

    traceSteps.forEach(s => {
      document.getElementById(s.id).className = "flow-step";
    });

    setPipelineStep("p-trace", "active");

    for (let i = 0; i < 3; i++) {
      const step = traceSteps[i];
      const el = document.getElementById(step.id);
      el.className = "flow-step active";
      await new Promise(r => setTimeout(r, step.delay));
      el.className = "flow-step done";
    }

    fetch("/api/trace", { method: "POST" })
      .then(res => res.json())
      .then(async data => {
        btnTrace.disabled = false;

        if (!data.success) {
          alert("Trace failed: " + data.error);
          setPipelineStep("p-trace", "");
          return;
        }

        // Finish remaining step flow
        for (let i = 3; i < traceSteps.length; i++) {
          const step = traceSteps[i];
          const el = document.getElementById(step.id);
          el.className = "flow-step active";
          await new Promise(r => setTimeout(r, step.delay));
          el.className = "flow-step done";
        }

        if (data.verified && data.attribution_status === "VERIFIED") {
          setPipelineStep("p-trace", "completed");
          setPipelineStep("p-attribute", "completed");

          document.getElementById("pipeline-status-chip").textContent = `ATTRIBUTION VERIFIED: ${data.recipient}`;
          document.getElementById("pipeline-status-chip").className = "chip chip-success";

          // Populate Result Card
          document.getElementById("trace-rec").textContent = data.recipient;
          document.getElementById("trace-sess").textContent = data.session_id;
          document.getElementById("trace-wmid").textContent = data.watermark_id;
          document.getElementById("trace-doc-match").textContent = `✓ ${data.document_match}`;
          document.getElementById("trace-sig").textContent = `✓ ${data.signature_valid}`;
          document.getElementById("trace-merkle").textContent = `✓ ${data.merkle_proof_valid}`;
          document.getElementById("trace-quorum").textContent = `✓ ${data.validator_quorum}`;
          document.getElementById("trace-block").textContent = `#${data.block_height} (${data.block_hash.slice(0, 12)}...)`;
          document.getElementById("trace-ber").textContent = data.bit_error_rate;

          // Evidence links
          document.getElementById("evidence-filename").textContent = data.evidence_json_filename;
          linkDownloadEvidence.href = data.evidence_json_url;
          btnModalDownload.href = data.evidence_json_url;

          currentEvidenceBundle = data.evidence_bundle;
          currentEvidenceReport = data.evidence_report;

          document.getElementById("trace-result-success").style.display = "block";
          document.getElementById("card-trace").className = "card full-width forensic-hero verified";

        } else {
          setPipelineStep("p-trace", "completed");
          setPipelineStep("p-attribute", "");

          document.getElementById("pipeline-status-chip").textContent = "ATTRIBUTION NOT VERIFIED";
          document.getElementById("pipeline-status-chip").className = "chip chip-danger";

          document.getElementById("trace-fail-wm").textContent = data.watermark_id || "NOT FOUND";
          document.getElementById("trace-fail-doc").textContent = data.document_match;
          document.getElementById("trace-fail-subtitle").textContent = data.attribution_status;

          document.getElementById("trace-result-failed").style.display = "block";
          document.getElementById("card-trace").className = "card full-width forensic-hero failed";
        }
      })
      .catch(err => {
        btnTrace.disabled = false;
        alert("Trace error: " + err.message);
      });
  });

  // MODAL LOGIC
  btnViewEvidence.addEventListener("click", () => {
    if (!currentEvidenceReport && !currentEvidenceBundle) return;
    const jsonStr = JSON.stringify(currentEvidenceBundle, null, 2);
    modalContent.textContent = currentEvidenceReport + "\n\n" + "=".repeat(80) + "\nJSON EVIDENCE BUNDLE (MACHINE-READABLE):\n" + "=".repeat(80) + "\n" + jsonStr;
    evidenceModal.classList.add("open");
  });

  btnCloseModal.addEventListener("click", () => {
    evidenceModal.classList.remove("open");
  });

  evidenceModal.addEventListener("click", (e) => {
    if (e.target === evidenceModal) {
      evidenceModal.classList.remove("open");
    }
  });

  // ONE-CLICK LIVE DEMO
  btnFullDemo.addEventListener("click", async () => {
    btnFullDemo.disabled = true;
    btnFullDemo.innerHTML = "<span>⏳</span> RUNNING LIVE DEMO...";

    // Step 1: Encrypt
    btnEncrypt.click();
    await new Promise(r => setTimeout(r, 1200));

    // Step 2: Decrypt
    btnDecrypt.click();
    await new Promise(r => setTimeout(r, 3500));

    // Step 3: Trace
    btnTrace.click();
    await new Promise(r => setTimeout(r, 3000));

    btnFullDemo.disabled = false;
    btnFullDemo.innerHTML = "<span>⚡</span> RUN FULL DEMO";
  });
});
