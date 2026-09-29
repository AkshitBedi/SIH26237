"""Run an isolated end-to-end demo without deleting earlier demo artifacts."""

import os
import sys
import subprocess
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(ROOT_DIR)
sys.path.insert(0, ROOT_DIR)


def print_banner(step_num: int, title: str):
    print("\n" + "=" * 80)
    print(f"  STEP {step_num}: {title.upper()}")
    print("=" * 80)


def run_command(command, label):
    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT_DIR, env=child_env,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.returncode:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
        raise RuntimeError(f"Demo stopped at {label} (exit code {result.returncode}).")
    return result


def main():
    print("=" * 80)
    print("  SIH PROBLEM STATEMENT 26237: LOCAL PROTOTYPE DEMONSTRATION")
    print("  Cryptographic Attribution and Auditable Decryption Provenance")
    print("  Stack: NIST FIPS 203 ML-KEM-768 | FIPS 204 ML-DSA-65 | SHA3-256 | AES-256-GCM")
    print("=" * 80)

    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1_000_000:06d}"
    run_dir = os.path.join("demo", "runs", run_id)
    keystore_dir = os.path.join(run_dir, "keystores")
    ledger_dir = os.path.join(run_dir, "ledger_data")
    package_path = os.path.join(run_dir, "packages", "confidential_brief.pqcpack")
    released_path = os.path.join(run_dir, "decrypted", "REC-047_document.png")
    leaked_path = os.path.join(run_dir, "leaks", "leaked_document.png")
    evidence_dir = os.path.join(run_dir, "evidence")
    sample_path = os.path.join("demo", "sample_documents", "confidential_brief.png")

    def cli(*args):
        return [
            sys.executable, "-m", "src.cli.main",
            "--keystore", keystore_dir,
            "--ledger", ledger_dir,
            *args,
        ]

    print(f"Run artifacts will be saved under: {run_dir}")

    print_banner(1, "Initialize Isolated Demo Identities")
    run_command(cli("setup-demo"), "identity setup")

    print_banner(2, "Encrypt Document for REC-001, REC-002, and REC-047")
    run_command(cli(
        "encrypt", "--input", sample_path,
        "--recipients", "REC-001,REC-002,REC-047",
        "--sender", "SENDER-HQ", "--output", package_path,
    ), "encryption")

    print_banner(3, "Inspect Distribution Package")
    run_command(cli("distribute", "--package", package_path), "package inspection")

    print_banner(4, "REC-047 Decrypts Through Commit-Before-Release")
    run_command(cli(
        "decrypt", "--package", package_path,
        "--recipient", "REC-047", "--output", released_path,
    ), "decryption and ledger commit")

    print_banner(5, "Inspect Offline Permissioned Ledger")
    run_command(cli("ledger-status"), "ledger verification")

    print_banner(6, "Simulate Screenshot Leak")
    run_command([
        sys.executable, "demo/simulate_leak.py",
        "--input", released_path,
        "--attack", "screenshot",
        "--output", leaked_path,
    ], "leak simulation")

    print_banner(7, "Trace Leak and Export Evidence")
    run_command(cli(
        "trace", leaked_path,
        "--reference", sample_path,
        "--evidence-dir", evidence_dir,
    ), "forensic trace")

    print_banner(8, "Verify Fresh Session and Watermark IDs")
    run_command(cli(
        "decrypt", "--package", package_path,
        "--recipient", "REC-047",
        "--output", os.path.join(run_dir, "decrypted", "REC-047_document_session2.png"),
    ), "second decryption session")

    print("\n" + "=" * 80)
    print("  [+] DEMO COMPLETED: all commands exited successfully.")
    print(f"  Artifacts preserved at: {os.path.abspath(run_dir)}")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"[-] {error}", file=sys.stderr)
        sys.exit(1)
