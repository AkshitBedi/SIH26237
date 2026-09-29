document.addEventListener("DOMContentLoaded", () => {
  const byId = (id) => document.getElementById(id);
  const buttons = {
    encrypt: byId("btn-encrypt"),
    decrypt: byId("btn-decrypt"),
    leak: byId("btn-apply-leak"),
    trace: byId("btn-trace"),
    fullDemo: byId("btn-full-demo"),
    refresh: byId("btn-reset"),
    viewEvidence: byId("btn-view-evidence"),
    closeModal: byId("btn-close-modal"),
  };
  let evidenceBundle = null;
  let evidenceReport = "";
  let busy = false;

  function notice(message, kind = "info") {
    const box = byId("app-notice");
    box.textContent = message;
    box.className = `notice notice-${kind}`;
    box.hidden = false;
    box.focus();
  }

  function clearNotice() {
    byId("app-notice").hidden = true;
  }

  async function requestJSON(url, options = {}) {
    const response = await fetch(url, options);
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(`The local service returned an unreadable response (${response.status}).`);
    }
    if (!response.ok || data.success === false) {
      const error = new Error(data.error || `The local service returned ${response.status}.`);
      error.type = data.error_type;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function postJSON(url, payload) {
    return requestJSON(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  function setBusy(active, button = null, label = "Working…") {
    busy = active;
    Object.values(buttons).forEach((item) => {
      if (item) item.disabled = active;
    });
    if (button) {
      button.dataset.originalLabel ||= button.innerHTML;
      button.innerHTML = active ? `<span class="spinner" aria-hidden="true"></span>${label}` : button.dataset.originalLabel;
    }
    document.body.setAttribute("aria-busy", String(active));
  }

  function jsonButtonState(button, label) {
    if (button) button.innerHTML = label;
  }

  function setPipelineStep(id, state) {
    const el = byId(id);
    if (!el) return;
    el.classList.remove("active", "completed", "failed");
    if (state) el.classList.add(state);
  }

  function setPipeline(ids, state) {
    ids.forEach((id) => setPipelineStep(id, state));
  }

  function resetPipeline() {
    setPipeline(["p-encrypt", "p-distribute", "p-authenticate", "p-commit", "p-watermark", "p-release", "p-leak", "p-trace", "p-attribute"], "");
    byId("pipeline-status-chip").textContent = "READY • LOCAL SERVICE";
    byId("pipeline-status-chip").className = "chip chip-info";
  }

  function resetFlow(ids) {
    ids.forEach((id) => {
      const el = byId(id);
      if (el) el.className = "flow-step";
    });
  }

  function setImage(id, url) {
    const image = byId(id);
    image.onload = () => { image.hidden = false; image.closest(".preview-box").querySelector(".preview-empty")?.setAttribute("hidden", ""); };
    image.onerror = () => {
      image.hidden = true;
      const empty = image.closest(".preview-box").querySelector(".preview-empty");
      if (empty) empty.hidden = false;
    };
    image.src = url;
  }

  function clearResults() {
    ["encrypt-result", "decrypt-result", "decrypt-error", "trace-result-success", "trace-result-failed"].forEach((id) => { byId(id).hidden = true; });
    byId("decrypt-flow").hidden = true;
    byId("trace-flow").hidden = true;
    byId("dec-img-preview").hidden = true;
    byId("leak-img-preview").hidden = true;
    byId("decrypted-empty").hidden = false;
    byId("leak-empty").hidden = false;
    byId("card-trace").classList.remove("verified", "failed");
    evidenceBundle = null;
    evidenceReport = "";
    resetPipeline();
  }

  async function refreshStatus() {
    const data = await requestJSON("/api/status");
    byId("service-status").textContent = data.status === "ONLINE" ? "LOCAL SERVICE READY" : "LOCAL SERVICE UNAVAILABLE";
    byId("service-status").className = `chip ${data.status === "ONLINE" ? "chip-success" : "chip-danger"}`;
    byId("ledger-height").textContent = `Ledger height ${data.ledger_height}`;
    if (data.has_decrypted) {
      setImage("dec-img-preview", `/api/image/decrypted?recipient=REC-047&t=${Date.now()}`);
    }
    if (data.has_leak) setImage("leak-img-preview", `/api/image/leaked?t=${Date.now()}`);
    return data;
  }

  function hideTraceResults() {
    byId("trace-result-success").hidden = true;
    byId("trace-result-failed").hidden = true;
  }

  function renderTrace(data) {
    const checks = data.verified && data.attribution_status === "VERIFIED";
    byId("trace-result-success").hidden = !checks;
    byId("trace-result-failed").hidden = checks;
    byId("card-trace").classList.toggle("verified", checks);
    byId("card-trace").classList.toggle("failed", !checks);
    byId("pipeline-status-chip").textContent = checks ? `ATTRIBUTION VERIFIED • ${data.recipient}` : `ATTRIBUTION ${data.attribution_status || "NOT VERIFIED"}`;
    byId("pipeline-status-chip").className = `chip ${checks ? "chip-success" : "chip-danger"}`;

    const stages = [
      ["tf-extract", Boolean(data.watermark_found)],
      ["tf-ecc", Boolean(data.watermark_found)],
      ["tf-lookup", Boolean(data.session_id && !["UNKNOWN", "UNRECORDED"].includes(data.session_id))],
      ["tf-dsa", Boolean(data.signature_valid)],
      ["tf-merkle", Boolean(data.merkle_proof_valid && data.block_valid)],
      ["tf-quorum", Boolean(data.validator_quorum_valid)],
      ["tf-attr", Boolean(data.verified)],
    ];
    stages.forEach(([id, passed]) => { byId(id).className = `flow-step ${passed ? "done" : "failed"}`; });

    if (checks) {
      byId("trace-rec").textContent = data.recipient;
      byId("trace-sess").textContent = data.session_id;
      byId("trace-wmid").textContent = data.watermark_id;
      byId("trace-doc-match").textContent = data.document_match;
      byId("trace-sig").textContent = data.signature_valid ? "VALID" : "INVALID";
      byId("trace-merkle").textContent = data.merkle_proof_valid ? "VALID" : "INVALID";
      byId("trace-quorum").textContent = `${data.validator_quorum}${data.validator_quorum_valid ? " • VALID" : " • FAILED"}`;
      byId("trace-block").textContent = `#${data.block_height} • ${(data.block_hash || "").slice(0, 12)}…`;
      byId("trace-ber").textContent = data.bit_error_rate;
      byId("evidence-filename").textContent = data.evidence_json_filename;
      byId("link-download-evidence").href = data.evidence_json_url;
      byId("btn-modal-download").href = data.evidence_json_url;
    } else {
      byId("trace-fail-wm").textContent = data.watermark_id || "NOT FOUND";
      byId("trace-fail-doc").textContent = data.document_match || "NOT VERIFIED";
      byId("trace-fail-subtitle").textContent = data.attribution_status || "Verification failed";
      byId("trace-fail-recipient").textContent = data.recipient || "UNKNOWN";
    }
    evidenceBundle = data.evidence_bundle || null;
    evidenceReport = data.evidence_report || "";
  }

  async function encrypt() {
    const recipients = ["rec-001", "rec-002", "rec-047"].filter((id) => byId(id).checked).map((id) => id.toUpperCase().replace("-", "-"));
    if (!recipients.length) throw new Error("Select at least one recipient before encrypting.");
    const result = await postJSON("/api/encrypt", { recipients });
    byId("enc-doc-hash").textContent = result.document_hash;
    byId("enc-recipients").textContent = result.capsule_recipients.join(", ");
    byId("enc-pkg-path").textContent = result.package_path;
    byId("enc-signature").textContent = result.sender_signature_present ? "Manifest signature created" : "Manifest signature missing";
    byId("encrypt-result").hidden = false;
    setPipeline(["p-encrypt", "p-distribute"], "completed");
    return result;
  }

  async function decrypt() {
    const recipient = byId("decrypt-recipient-select").value;
    const faultValue = byId("faulty-validator-select").value;
    const faultyValidators = faultValue ? faultValue.split(",") : [];
    const result = await postJSON("/api/decrypt", { recipient_id: recipient, faulty_validators: faultyValidators });
    ["df-auth", "df-sess", "df-sign", "df-ledger", "df-quorum", "df-commit", "df-watermark", "df-release"].forEach((id) => byId(id).className = "flow-step done");
    setPipeline(["p-authenticate", "p-commit", "p-watermark", "p-release"], "completed");
    byId("dec-rec").textContent = result.recipient_id;
    byId("dec-sess").textContent = result.session_id;
    byId("dec-wmid").textContent = result.watermark_id;
    byId("dec-block").textContent = `#${result.block_height}`;
    byId("dec-quorum").textContent = `${result.quorum_count} • ${result.validator_signature_count} signatures`;
    byId("ledger-height").textContent = `Ledger height ${result.block_height}`;
    byId("dec-sig").textContent = result.signature_valid ? "ACCEPTED AT COMMIT" : "NOT VERIFIED";
    byId("decrypt-result").hidden = false;
    setImage("dec-img-preview", result.image_url);
    byId("decrypt-flow").hidden = false;
    byId("decrypt-error").hidden = true;
    byId("pipeline-status-chip").textContent = "PROVENANCE COMMITTED • RELEASE AUTHORIZED";
    byId("pipeline-status-chip").className = "chip chip-success";
    return result;
  }

  async function simulateLeak() {
    const result = await postJSON("/api/simulate-leak", {
      attack: byId("leak-attack-select").value,
      recipient_id: byId("decrypt-recipient-select").value,
    });
    setPipelineStep("p-leak", "completed");
    byId("leak-caption").textContent = `Simulated ${result.attack.toUpperCase()} • ${result.dimensions}`;
    setImage("leak-img-preview", result.leak_url);
    return result;
  }

  async function trace() {
    const data = await postJSON("/api/trace", {});
    setPipeline(["p-trace", "p-attribute"], data.verified ? "completed" : "failed");
    renderTrace(data);
    byId("trace-flow").hidden = false;
    return data;
  }

  async function runAction(button, label, action) {
    if (busy) return;
    clearNotice();
    setBusy(true, button, label);
    try {
      await action();
    } catch (error) {
      if (button === buttons.fullDemo) {
        setPipeline(["p-encrypt", "p-distribute", "p-authenticate", "p-commit", "p-watermark", "p-release", "p-leak", "p-trace", "p-attribute"], "failed");
      }
      notice(error.message || "The operation failed. No success result was recorded.", "error");
    } finally {
      setBusy(false, button);
    }
  }

  buttons.encrypt.addEventListener("click", () => runAction(buttons.encrypt, "Encrypting locally…", async () => {
    byId("encrypt-result").hidden = true;
    setPipeline(["p-encrypt", "p-distribute"], "active");
    const result = await encrypt();
    notice(`Encrypted package created for ${result.capsule_recipients.length} recipient(s).`, "success");
  }));

  buttons.decrypt.addEventListener("click", () => runAction(buttons.decrypt, "Waiting for commit…", async () => {
    byId("decrypt-result").hidden = true;
    byId("decrypt-error").hidden = true;
    byId("decrypt-flow").hidden = false;
    resetFlow(["df-auth", "df-sess", "df-sign", "df-ledger", "df-quorum", "df-commit", "df-watermark", "df-release"]);
    setPipeline(["p-authenticate", "p-commit", "p-watermark", "p-release"], "active");
    try {
      const result = await decrypt();
      notice(`Ledger commit confirmed at block #${result.block_height}. Watermarked release authorized.`, "success");
    } catch (error) {
      byId("decrypt-error").hidden = false;
      byId("dec-error-text").textContent = error.message;
      if (error.type === "COMMIT_BEFORE_RELEASE_VIOLATION") {
        ["df-auth", "df-sess", "df-sign", "df-ledger"].forEach((id) => byId(id).className = "flow-step done");
        byId("df-quorum").className = "flow-step failed";
        ["df-commit", "df-watermark", "df-release"].forEach((id) => byId(id).className = "flow-step failed");
        setPipelineStep("p-authenticate", "completed");
        setPipelineStep("p-commit", "failed");
        setPipelineStep("p-watermark", "failed");
        setPipelineStep("p-release", "failed");
      } else {
        byId("df-auth").className = "flow-step failed";
        byId("df-release").className = "flow-step failed";
        setPipelineStep("p-authenticate", "failed");
        setPipelineStep("p-release", "failed");
      }
      byId("df-release").textContent = "RELEASE NOT AUTHORIZED";
      notice(error.message, "error");
    }
  }));

  buttons.leak.addEventListener("click", () => runAction(buttons.leak, "Simulating leak…", async () => {
    setPipelineStep("p-leak", "active");
    const result = await simulateLeak();
    notice(`Leak simulation complete (${result.attack}).`, "success");
  }));

  buttons.trace.addEventListener("click", () => runAction(buttons.trace, "Verifying evidence…", async () => {
    hideTraceResults();
    byId("trace-flow").hidden = false;
    resetFlow(["tf-extract", "tf-ecc", "tf-lookup", "tf-dsa", "tf-merkle", "tf-quorum", "tf-attr"]);
    setPipelineStep("p-trace", "active");
    const result = await trace();
    notice(result.verified ? `Attribution verified for ${result.recipient}.` : "Attribution could not be verified. Review the failed checks below.", result.verified ? "success" : "error");
  }));

  buttons.fullDemo.addEventListener("click", () => runAction(buttons.fullDemo, "Running full demo…", async () => {
    clearResults();
    ["p-encrypt", "p-distribute", "p-authenticate", "p-commit", "p-watermark", "p-release", "p-leak", "p-trace"].forEach((id) => setPipelineStep(id, "active"));
    const result = await postJSON("/api/run-full-demo", {});
    const enc = result.step_encrypt;
    const dec = result.step_decrypt;
    const tr = result.step_trace;
    byId("enc-doc-hash").textContent = enc.doc_hash;
    byId("enc-recipients").textContent = enc.recipients.join(", ");
    byId("enc-pkg-path").textContent = result.package_path;
    byId("enc-signature").textContent = enc.sender_signature_present ? "Manifest signature created" : "Manifest signature missing";
    byId("encrypt-result").hidden = false;
    byId("dec-rec").textContent = dec.recipient;
    byId("dec-sess").textContent = dec.session_id;
    byId("dec-wmid").textContent = dec.watermark_id;
    byId("dec-block").textContent = `#${dec.block_height}`;
    byId("dec-quorum").textContent = `${dec.quorum} • ${dec.validator_signature_count} signatures`;
    byId("ledger-height").textContent = `Ledger height ${result.ledger_height}`;
    byId("dec-sig").textContent = dec.signature_valid ? "ACCEPTED AT COMMIT" : "NOT VERIFIED";
    byId("decrypt-result").hidden = false;
    byId("decrypt-flow").hidden = false;
    ["df-auth", "df-sess", "df-sign", "df-ledger", "df-quorum", "df-commit", "df-watermark", "df-release"].forEach((id) => byId(id).className = "flow-step done");
    setImage("dec-img-preview", `/api/image/decrypted?recipient=REC-047&t=${Date.now()}`);
    setImage("leak-img-preview", `/api/image/leaked?t=${Date.now()}`);
    byId("leak-caption").textContent = "Simulated screenshot capture • generated by full demo";
    byId("trace-flow").hidden = false;
    renderTrace(tr);
    byId("trace-flow").hidden = false;
    setPipeline(["p-encrypt", "p-distribute", "p-authenticate", "p-commit", "p-watermark", "p-release", "p-leak", "p-trace", "p-attribute"], tr.verified ? "completed" : "failed");
    notice(tr.verified ? `Full demo completed. Attribution verified for ${tr.recipient}.` : "Full demo ran, but attribution was not verified.", tr.verified ? "success" : "error");
  }));

  buttons.refresh.addEventListener("click", () => runAction(buttons.refresh, "Checking local service…", async () => {
    const data = await refreshStatus();
    notice(`Local service ready. Ledger height ${data.ledger_height}.`, "success");
  }));

  buttons.viewEvidence.addEventListener("click", () => {
    if (!evidenceBundle) return;
    byId("modal-evidence-content").textContent = `${evidenceReport}\n\n${"=".repeat(72)}\nMACHINE-READABLE JSON EVIDENCE\n${"=".repeat(72)}\n${JSON.stringify(evidenceBundle, null, 2)}`;
    byId("evidence-modal").classList.add("open");
    byId("evidence-modal").setAttribute("aria-hidden", "false");
    buttons.closeModal.focus();
  });

  function closeEvidence() {
    byId("evidence-modal").classList.remove("open");
    byId("evidence-modal").setAttribute("aria-hidden", "true");
    buttons.viewEvidence.focus();
  }
  buttons.closeModal.addEventListener("click", closeEvidence);
  byId("evidence-modal").addEventListener("click", (event) => { if (event.target === byId("evidence-modal")) closeEvidence(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && byId("evidence-modal").classList.contains("open")) closeEvidence(); });

  clearResults();
  refreshStatus().catch((error) => {
    byId("service-status").textContent = "LOCAL SERVICE UNAVAILABLE";
    byId("service-status").className = "chip chip-danger";
    notice(error.message, "error");
  });
});
