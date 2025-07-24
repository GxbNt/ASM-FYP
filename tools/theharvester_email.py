import os
import sys
import subprocess
import json

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")

def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def extract_emails_to_json(json_file, output_file):
    try:
        with open(json_file, "r") as f:
            data = json.load(f)

        emails = sorted(set(data.get("emails", [])))

        with open(output_file, "w") as f_out:
            json.dump({"emails": emails}, f_out, indent=2)

    except Exception as e:
        print(f"[!] Failed to extract emails: {e}")

def run_theharvester(domain):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    result_file = os.path.join(BASE_DIR, "results.json")
    email_output_file = os.path.join(OUTPUT_DIR, f"{domain}_emails.json")

    command = [
        "theharvester",
        "-d", domain,
        "-b", "all",
        "-f", result_file.replace(".json", "")
    ]

    silent_run(command)
    extract_emails_to_json(result_file, email_output_file)

    # Optionally clean up
    try:
        os.remove(result_file)
    except FileNotFoundError:
        pass

    xml_file = os.path.join(BASE_DIR, "results.xml")
    try:
        os.remove(xml_file)
    except FileNotFoundError:
        pass


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 theharvester_emails.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    run_theharvester(domain)

if __name__ == "__main__":
    main()
