#!/usr/bin/env python3
"""
Advanced Reconnaissance Automation Tool
Main entry point for all reconnaissance tools
"""

import argparse
import os
import sys
import logging
import time
from datetime import datetime
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import your tools as modules
import subdomain
import urlfinder
import naabu
import httpx
import theharvester_email
import gobuster_fuzz
import nuclei_dast
import nuclei
import chatbot
import parser

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('recon_tool.log'), logging.StreamHandler()]
)

class ReconTool:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def run_subdomain(self, domain):
        self.logger.info("[*] Running Subdomain Enumeration...")
        subdomain.main(domain)

    def run_httpx(self, domain):
        self.logger.info("[*] Running HTTPx Check...")
        httpx.run_httpx(domain)

    def run_urlfinder(self, domain):
        self.logger.info("[*] Running URL Finder...")
        urlfinder.run_urlfinder(domain)

    def run_naabu(self, domain):
        self.logger.info("[*] Running Naabu Port Scan...")
        naabu.run_naabu(domain)

    def run_theharvester(self, domain):
        self.logger.info("[*] Running theHarvester Email Harvest...")
        theharvester_email.run_theharvester(domain)

    def run_gobuster(self, domain):
        self.logger.info("[*] Running Gobuster Fuzz...")
        gobuster_fuzz.run_gobuster(domain)

    def run_nuclei_dast(self, domain):
        self.logger.info("[*] Running Nuclei DAST...")
        nuclei_dast.run_nuclei_dast(domain)

    def run_nuclei(self, domain):
        self.logger.info("[*] Running Nuclei Scan...")
        nuclei.run_nuclei(domain)

    def run_all(self, domain):
        import concurrent.futures
        start = time.time()
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # 1. Start subdomain and theharvester in parallel
                future_subdomain = executor.submit(self.run_subdomain, domain)
                future_theharvester = executor.submit(self.run_theharvester, domain)

                # 2. When subdomain is done, run naabu, urlfinder, gobuster, nuclei in parallel
                def after_subdomain():
                    f_naabu = executor.submit(self.run_naabu, domain)
                    f_urlfinder = executor.submit(self.run_urlfinder, domain)
                    f_gobuster = executor.submit(self.run_gobuster, domain)
                    f_nuclei = executor.submit(self.run_nuclei, domain)
                    return f_naabu, f_urlfinder, f_gobuster, f_nuclei

                future_subdomain.result()  # Wait for subdomain to finish
                f_naabu, f_urlfinder, f_gobuster, f_nuclei = after_subdomain()

                # 3. When urlfinder is done, run nuclei_dast
                def after_urlfinder():
                    f_urlfinder.result()
                    return executor.submit(self.run_nuclei_dast, domain)
                f_nuclei_dast = after_urlfinder()

                # 4. When naabu is done, run httpx
                def after_naabu():
                    f_naabu.result()
                    return executor.submit(self.run_httpx, domain)
                f_httpx = after_naabu()

                # Wait for all remaining futures to finish
                concurrent.futures.wait([
                    future_theharvester,
                    f_gobuster,
                    f_nuclei,
                    f_nuclei_dast,
                    f_httpx
                ])
        except Exception as e:
            self.logger.error(f"[!] Error during full run: {e}")
        end = time.time()
        self.logger.info(f"[+] Completed all tools in {end - start:.2f} seconds.")

    def start_chatbot(self):
        self.logger.info("[*] Starting Chatbot...")
        chatbot.chatbot()

def main():
    parser_obj = argparse.ArgumentParser(description="Recon Automation Tool")
    parser_obj.add_argument("-d", "--domain", help="Target domain")
    parser_obj.add_argument("--subdomain", action="store_true", help="Run Subdomain Enumeration")
    parser_obj.add_argument("--urlfinder", action="store_true", help="Run URL Finder")
    parser_obj.add_argument("--naabu", action="store_true", help="Run Naabu Port Scan")
    parser_obj.add_argument("--httpx", action="store_true", help="Run HTTPx Check")
    parser_obj.add_argument("--theharvester", action="store_true", help="Run theHarvester Email Harvest")
    parser_obj.add_argument("--gobuster", action="store_true", help="Run Gobuster Fuzz")
    parser_obj.add_argument("--nuclei_dast", action="store_true", help="Run Nuclei DAST")
    parser_obj.add_argument("--nuclei", action="store_true", help="Run Nuclei Scan")
    parser_obj.add_argument("--all", action="store_true", help="Run all tools step by step")

    args = parser_obj.parse_args()

    recon = ReconTool()


    if not args.domain and not args.chatbot:
        print("[!] Domain is required unless using chatbot")
        return

    domain = args.domain

    # Run based on flags
    if args.all:
        recon.run_all(domain)
    else:
        if args.subdomain:
            recon.run_subdomain(domain)
        if args.urlfinder:
            recon.run_urlfinder(domain)
        if args.naabu:
            recon.run_naabu(domain)
        if args.httpx:
            recon.run_httpx(domain)
        if args.theharvester:
            recon.run_theharvester(domain)
        if args.gobuster:
            recon.run_gobuster(domain)
        if args.nuclei_dast:
            recon.run_nuclei_dast(domain)
        if args.nuclei:
            recon.run_nuclei(domain)

if __name__ == "__main__":
    main()
