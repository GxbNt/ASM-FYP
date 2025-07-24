import os
import sys
import subprocess

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")

def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_urlfinder(domain):
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_urlfinder.json")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    command = [
        "urlfinder",
        "-d", domain,
        "-j",
        "-o", output_file,
        "-silent"
    ]

    silent_run(command)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 urlfinder.py <domain>")
        sys.exit(1)

    run_urlfinder(sys.argv[1])

if __name__ == "__main__":
    main()
