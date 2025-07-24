import os
import json

DATA_DIR = "../Outputs"

def read_json_lines(filepath):
    """Reads a JSON file line-by-line as separate objects (used for httpx, naabu)."""
    try:
        with open(filepath, 'r') as f:
            return [json.loads(line.strip()) for line in f if line.strip()]
    except Exception as e:
        return f"[!] Failed to read {filepath}: {e}"

def read_directory_fuzz_file(filepath):
    """Parses lines like '/.git/                (Status: 200) [Size: 921]'."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return f"[!] Failed to read {filepath}: {e}"

def get_alive_urls(domain):
    file = os.path.join(DATA_DIR, f"{domain}_httpx.json")
    entries = read_json_lines(file)
    if isinstance(entries, str): return entries  # error message

    urls = [entry["url"] for entry in entries if entry.get("status_code") == 200]
    if not urls:
        return f"No alive URLs (status 200) found for {domain}."
    return f"{len(urls)} alive URLs found:\n" + "\n".join(urls)

def get_open_ports(domain):
    file = os.path.join(DATA_DIR, f"{domain}_naabu.json")
    entries = read_json_lines(file)
    if isinstance(entries, str): return entries

    ports = sorted(set(str(entry["port"]) for entry in entries if entry.get("host", "").endswith(domain)))
    if not ports:
        return f"No open ports found for {domain}."
    return f"{len(ports)} open ports found for {domain}:\n" + ", ".join(ports)

def get_fuzzed_paths(domain):
    file = os.path.join(DATA_DIR, f"{domain}_directory_fuzz.json")
    lines = read_directory_fuzz_file(file)
    if isinstance(lines, str): return lines

    return f"{len(lines)} paths found via directory fuzzing for {domain}:\n" + "\n".join(lines)

def get_harvested_emails(domain):
    """Get harvested emails for a domain"""
    file = os.path.join(DATA_DIR, f"{domain}_emails.json")
    try:
        with open(file, 'r') as f:
            data = json.load(f)
        
        emails = data.get('emails', [])
        if not emails:
            return f"No emails found for {domain}."
        
        return f"{len(emails)} emails found for {domain}:\n" + "\n".join(emails)
    except FileNotFoundError:
        return f"No email data found for {domain}. Run email harvesting first."
    except Exception as e:
        return f"[!] Failed to read email data for {domain}: {e}"

def get_subdomains(domain):
    """Get subdomains for a domain"""
    # Try to read from the subdomain file first (resolved subdomains)
    subdomain_file = os.path.join(DATA_DIR, f"{domain}_subdomain.txt")
    overall_file = os.path.join(DATA_DIR, f"{domain}_overall_subdomain.txt")
    
    # Try resolved subdomains first
    try:
        with open(subdomain_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        if subdomains:
            return f"{len(subdomains)} resolved subdomains found for {domain}:\n" + "\n".join(subdomains)
    except FileNotFoundError:
        pass
    except Exception as e:
        return f"[!] Failed to read resolved subdomain data for {domain}: {e}"
    
    # Try overall subdomains (unresolved)
    try:
        with open(overall_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        if subdomains:
            return f"{len(subdomains)} total subdomains found for {domain} (may include unresolved):\n" + "\n".join(subdomains)
    except FileNotFoundError:
        return f"No subdomain data found for {domain}. Run subdomain enumeration first."
    except Exception as e:
        return f"[!] Failed to read subdomain data for {domain}: {e}"
    
    return f"No subdomains found for {domain}."
