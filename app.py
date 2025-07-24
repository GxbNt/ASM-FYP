from flask import Flask, render_template, request, redirect, url_for, flash
import os
import subprocess
import re
import ast

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production

OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Outputs')
TOOLS_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'main.py')

# Helper to get all files for a domain
def get_domain_files(domain):
    files = {}
    for fname in os.listdir(OUTPUTS_DIR):
        if fname.startswith(domain + "_"):
            files[fname] = os.path.join(OUTPUTS_DIR, fname)
    return files

# Helper to read file content (text or json)
def read_file_content(filepath):
    if filepath.endswith('.json'):
        try:
            import json
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            return f"[Error reading JSON: {e}]"
    else:
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except Exception as e:
            return f"[Error reading file: {e}]"

# --- New helpers for pretty results ---
def read_lines(filepath):
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return [f"[Error reading file: {e}]"]

def read_json_lines(filepath):
    import json
    lines = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except Exception as e:
                        lines.append({'error': str(e), 'raw': line})
    except Exception as e:
        lines.append({'error': str(e)})
    return lines

def clean_evidence_text(text):
    if not text:
        return ''
    import re
    # Remove tabs, newlines, carriage returns, and collapse multiple spaces
    cleaned = re.sub(r'[\t\n\r]+', ' ', text)
    cleaned = re.sub(r' +', ' ', cleaned)
    # Remove all leading whitespace (including tabs and spaces)
    cleaned = re.sub(r'^\s+', '', cleaned)
    return cleaned.strip()

def safe_parse_evidence(evidence):
    if not evidence:
        return []
    try:
        if evidence.startswith('[') and evidence.endswith(']'):
            import ast
            items = ast.literal_eval(evidence)
            return [clean_evidence_text(str(item)) for item in items]
        return [clean_evidence_text(evidence)]
    except Exception:
        return [clean_evidence_text(evidence)]

def parse_fuzzing_vulns(lines):
    parsed = []
    for line in lines:
        # Example: [type] [protocol] [severity] url [evidence] [extra] [method]
        m = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (\S+) (\[.*?\])? ?(\[.*?\])? ?(\[.*?\])?', line)
        if m:
            type_, proto, severity, url, evidence, extra, method = m.groups()
            parsed.append({
                'type': type_,
                'protocol': proto,
                'severity': severity,
                'url': url,
                'evidence': safe_parse_evidence(evidence),
                'extra': extra,
                'method': method
            })
        else:
            parsed.append({'raw': line})
    return parsed

def parse_nuclei_vulns(lines):
    parsed = []
    for line in lines:
        # Example: [type] [protocol] [severity] target [evidence]
        m = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] \[(.*?)\] (\S+)(?: (\[.*\]))?', line)
        if m:
            type_, proto, severity, extra, target, evidence = m.groups()
            parsed.append({
                'type': type_,
                'protocol': proto,
                'severity': severity,
                'extra': extra,
                'target': target,
                'evidence': safe_parse_evidence(evidence)
            })
        else:
            # fallback: try to parse without [extra]
            m2 = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (\S+)(?: (\[.*\]))?', line)
            if m2:
                type_, proto, severity, target, evidence = m2.groups()
                parsed.append({
                    'type': type_,
                    'protocol': proto,
                    'severity': severity,
                    'extra': '',
                    'target': target,
                    'evidence': safe_parse_evidence(evidence)
                })
            else:
                parsed.append({'raw': line})
    return parsed

def parse_fuzzing_dirs(lines):
    parsed = []
    for line in lines:
        m = re.match(r'(.+?) \(Status: (\d+)\)', line)
        if m:
            path, status = m.groups()
            parsed.append({
                'path': path.strip(),
                'status': status.strip()
            })
        else:
            parsed.append({'raw': line})
    return parsed

def parse_results(domain):
    data = {}
    # Active subdomains
    subdomain_file = os.path.join(OUTPUTS_DIR, f'{domain}_subdomain.txt')
    if os.path.exists(subdomain_file):
        data['active_subdomains'] = read_lines(subdomain_file)
    else:
        data['active_subdomains'] = []
    # All subdomains
    overall_file = os.path.join(OUTPUTS_DIR, f'{domain}_overall_subdomain.txt')
    if os.path.exists(overall_file):
        data['all_subdomains'] = read_lines(overall_file)
    else:
        data['all_subdomains'] = []
    # Open ports
    naabu_file = os.path.join(OUTPUTS_DIR, f'{domain}_naabu.json')
    if os.path.exists(naabu_file):
        data['open_ports'] = read_json_lines(naabu_file)
    else:
        data['open_ports'] = []
    # Directory fuzzing
    dirfuzz_file = os.path.join(OUTPUTS_DIR, f'{domain}_directory_fuzz.json')
    if os.path.exists(dirfuzz_file):
        lines = read_lines(dirfuzz_file)
        data['directories'] = lines
        data['directories_parsed'] = parse_fuzzing_dirs(lines)
    else:
        data['directories'] = []
        data['directories_parsed'] = []
    # URL finder
    urlfinder_file = os.path.join(OUTPUTS_DIR, f'{domain}_urlfinder.json')
    if os.path.exists(urlfinder_file):
        data['endpoints'] = read_json_lines(urlfinder_file)
    else:
        data['endpoints'] = []
    # Vulnerabilities (DAST)
    vuln_file = os.path.join(OUTPUTS_DIR, f'{domain}_vulnerabilities.json')
    if os.path.exists(vuln_file):
        lines = read_lines(vuln_file)
        data['fuzzing_vulns'] = lines
        data['fuzzing_vulns_parsed'] = parse_fuzzing_vulns(lines)
    else:
        data['fuzzing_vulns'] = []
        data['fuzzing_vulns_parsed'] = []
    # HTTPX (tech info)
    httpx_file = os.path.join(OUTPUTS_DIR, f'{domain}_httpx.json')
    if os.path.exists(httpx_file):
        data['httpx'] = read_json_lines(httpx_file)
    else:
        data['httpx'] = []
    # Nuclei (vulns)
    nuclei_file = os.path.join(OUTPUTS_DIR, f'{domain}_nuclei.json')
    if os.path.exists(nuclei_file):
        lines = read_lines(nuclei_file)
        data['nuclei_vulns'] = lines
        data['nuclei_vulns_parsed'] = parse_nuclei_vulns(lines)
    else:
        data['nuclei_vulns'] = []
        data['nuclei_vulns_parsed'] = []
    # Emails
    email_file = os.path.join(OUTPUTS_DIR, f'{domain}_emails.json')
    if os.path.exists(email_file):
        try:
            import json
            with open(email_file, 'r') as f:
                data_json = json.load(f)
            data['emails_parsed'] = data_json.get('emails', [])
        except Exception:
            data['emails_parsed'] = []
    else:
        data['emails_parsed'] = []
    return data

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            flash('Please enter a domain name.', 'danger')
            return redirect(url_for('index'))
        subdomain_file = os.path.join(OUTPUTS_DIR, f'{domain}_subdomain.txt')
        if os.path.exists(subdomain_file):
            # Parse and organize all results for this domain
            results = parse_results(domain)
            return render_template('results.html', domain=domain, results=results)
        else:
            try:
                subprocess.Popen(['python3', TOOLS_MAIN, '-d', domain, '--all'])
                flash(f'Scan started for {domain}. Please refresh this page after a while.', 'info')
            except Exception as e:
                flash(f'Failed to start scan: {e}', 'danger')
            return redirect(url_for('index'))
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') 