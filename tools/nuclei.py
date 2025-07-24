import os
import sys
import subprocess

# Set base directory paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "Outputs")

# Silent subprocess run
def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Main nuclei execution
def run_nuclei(domain):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    subdomain_file = os.path.join(OUTPUT_DIR, f"{domain}_subdomain.txt")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_nuclei.json")

    if not os.path.isfile(subdomain_file):
        return  # Silently exit if subdomain file not found

    if os.path.exists(output_file):
        os.remove(output_file)

    command = [
        "nuclei",
        "-list", subdomain_file,
        "-nc",
        "-silent",
        "-json-export", output_file
    ]

    silent_run(command)

# Script entry point
def main():
    if len(sys.argv) != 2:
        return  # Silently exit on incorrect usage

    domain = sys.argv[1]
    run_nuclei(domain)

if __name__ == "__main__":
    main()
