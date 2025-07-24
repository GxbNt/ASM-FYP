import os
import sys
import subprocess
import threading
import time
import shutil

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")
ONEFORALL_DIR = os.path.join(BASE_DIR, "OneForAll")
RESULTS_DIR = os.path.join(ONEFORALL_DIR, "results")


def silent_run(command, cwd=None, shell=False):
    subprocess.run(command, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=shell)


def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def run_subfinder(domain):
    out = os.path.join(OUTPUT_DIR, f"{domain}_subfinder.txt")
    silent_run(["subfinder", "-d", domain, "-o", out])


def run_oneforall(domain):
    silent_run(["python3", "oneforall.py", "--target", domain, "run"], cwd=ONEFORALL_DIR)


def extract_oneforall_subdomains(domain):
    csv_file = os.path.join(RESULTS_DIR, f"{domain}.csv")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_oneforall.txt")

    for _ in range(10):  # wait max 10 seconds
        if os.path.isfile(csv_file):
            break
        time.sleep(1)
    else:
        print(f"[!] OneForAll CSV not found: {csv_file}")
        return

    # Extract subdomain column (6th)
    cmd = f"cut -d',' -f6 '{csv_file}' | tail -n +2 | sort -u > '{output_file}'"
    silent_run(cmd, shell=True)


def merge_outputs(domain):
    paths = [
        os.path.join(OUTPUT_DIR, f"{domain}_subfinder.txt"),
        os.path.join(OUTPUT_DIR, f"{domain}_oneforall.txt")
    ]
    combined_file = os.path.join(OUTPUT_DIR, f"{domain}_overall_subdomain.txt")

    subdomains = set()
    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                subdomains.update(line.strip() for line in f if line.strip())

    with open(combined_file, "w") as f:
        f.writelines(f"{sub}\n" for sub in sorted(subdomains))


def resolve_with_puredns(domain):
    input_file = os.path.join(OUTPUT_DIR, f"{domain}_overall_subdomain.txt")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_subdomain.txt")

    if os.path.isfile(input_file):
        silent_run(["puredns", "resolve", input_file, "-w", output_file])

        # Append root domain as it always resolves
        with open(output_file, "a") as f:
            f.write(f"{domain}\n")


def clean_oneforall_results():
    for item in os.listdir(RESULTS_DIR):
        path = os.path.join(RESULTS_DIR, item)
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception:
            pass


def main(domain):
    ensure_dirs()

    # Run subfinder & oneforall concurrently
    threads = [
        threading.Thread(target=run_subfinder, args=(domain,)),
        threading.Thread(target=run_oneforall, args=(domain,))
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]

    extract_oneforall_subdomains(domain)
    merge_outputs(domain)
    resolve_with_puredns(domain)
    clean_oneforall_results()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain.py <domain>")
        sys.exit(1)
    main(sys.argv[1])
