import os
import sys
import subprocess

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")

def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_naabu(domain):
    input_file = os.path.join(OUTPUT_DIR, f"{domain}_subdomain.txt")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_naabu.json")

    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    command = [
        "naabu",
        "-l", input_file,
        "-p", "-",        
        "-json",
        "-o", output_file
    ]

    silent_run(command)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 naabu.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    run_naabu(domain)

if __name__ == "__main__":
    main()
