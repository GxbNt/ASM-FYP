import os
import sys
import subprocess
import json
import tempfile

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "Outputs")
NUCLEI_TEMPLATES = os.path.expanduser("~/nuclei-templates/dast/vulnerabilities/")

def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_nuclei_dast(domain):
    urlfinder_file = os.path.join(OUTPUT_DIR, f"{domain}_urlfinder.json")
    output_file = os.path.join(OUTPUT_DIR, f"{domain}_vulnerabilities.json")

    if not os.path.isfile(urlfinder_file):
        return  # Silent exit if input file missing

    urls = []
    try:
        with open(urlfinder_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    url = data.get("url")
                    if url:
                        urls.append(url)
                except json.JSONDecodeError:
                    continue
    except Exception:
        return  # Silent exit on error

    if not urls:
        return  # Silent exit if no URLs

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file.write("\n".join(urls))
        temp_file_path = temp_file.name

    command = [
        "nuclei",
        "-list", temp_file_path,
        "-dast",
        "-t", NUCLEI_TEMPLATES,
        "-nc",
        "-silent",
        "-json-export", output_file
    ]

    silent_run(command)

    try:
        os.remove(temp_file_path)
    except OSError:
        pass

def main():
    if len(sys.argv) != 2:
        return
    domain = sys.argv[1]
    run_nuclei_dast(domain)

if __name__ == "__main__":
    main()
