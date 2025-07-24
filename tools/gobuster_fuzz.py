import os
import sys
import subprocess

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")
WORDLIST = os.path.expanduser("~/SecLists/Discovery/Web-Content/big.txt")

def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_gobuster(domain):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_file = os.path.join(OUTPUT_DIR, f"{domain}_directory_fuzz.json")

    command = [
        "gobuster", 
        "-u", domain,
        "-w", WORDLIST,
        "-o", output_file,
        "-f", "json"
    ]

    silent_run(command)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 gobuster_fuzz.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    run_gobuster(domain)

if __name__ == "__main__":
    main()
