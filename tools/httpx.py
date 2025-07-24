import os
import sys
import subprocess
import json

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Outputs")


def silent_run(command):
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def extract_host_ports(naabu_json_path, hostport_txt_path):
    hostports = set()

    try:
        with open(naabu_json_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    host = data.get("host")
                    port = data.get("port")
                    if host and port:
                        hostports.add(f"{host}:{port}")
                except json.JSONDecodeError:
                    continue

        with open(hostport_txt_path, "w") as out:
            for entry in sorted(hostports):
                out.write(entry + "\n")

    except Exception as e:
        print(f"[!] Failed to extract host:port - {e}")


def run_httpx(domain):
    naabu_input = os.path.join(OUTPUT_DIR, f"{domain}_naabu.json")
    hostport_file = os.path.join(OUTPUT_DIR, f"{domain}_hostport.txt")
    httpx_output = os.path.join(OUTPUT_DIR, f"{domain}_httpx.json")

    if not os.path.isfile(naabu_input):
        print(f"[!] Missing input file: {naabu_input}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    extract_host_ports(naabu_input, hostport_file)

    command = [
        "httpx",
        "-l", hostport_file,
        "-sc", "-td", "-title", "-ip", "-fr",
        "-j",
        "-o", httpx_output
    ]
    silent_run(command)

    # Cleanup temp file
    try:
        os.remove(hostport_file)
    except OSError:
        pass


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 httpx.py <domain>")
        sys.exit(1)

    run_httpx(sys.argv[1])


if __name__ == "__main__":
    main()
