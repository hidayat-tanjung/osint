import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
from colorama import init, Fore, Style
import argparse
import socket
import subprocess
from datetime import datetime

init(autoreset=True)

class OSINTTool:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def get_whois_info(self, domain):
        """Robust WHOIS lookup with multiple fallbacks"""
        try:
            print(Fore.YELLOW + f"\nAttempting WHOIS lookup for {domain}...")
            
            # First try python-whois library
            try:
                domain_info = whois.whois(domain)
                if domain_info:
                    print(Fore.GREEN + "\nWHOIS Information (python-whois):")
                    for key, value in domain_info.items():
                        if value and not key.startswith('_'):
                            print(Fore.CYAN + f"{key.upper()}: {Fore.WHITE}{value}")
                    return domain_info
            except Exception as e:
                print(Fore.YELLOW + f"Python WHOIS failed: {e}. Trying system whois...")

            # Fallback to system whois command
            try:
                result = subprocess.run(
                    ["whois", domain],
                    timeout=10,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    print(Fore.GREEN + "\nWHOIS Raw Data (system whois):")
                    print(Fore.WHITE + result.stdout[:1000] + ("..." if len(result.stdout) > 1000 else ""))
                    return result.stdout
                else:
                    raise Exception(result.stderr)
            except FileNotFoundError:
                print(Fore.RED + "WHOIS command not found. Install with: sudo apt install whois")
            except subprocess.TimeoutExpired:
                print(Fore.RED + "WHOIS lookup timed out")

        except Exception as e:
            print(Fore.RED + f"\nWHOIS lookup completely failed: {e}")
        return None

    def get_dns_records(self, domain, record_type='A'):
        """DNS record lookup with comprehensive error handling"""
        try:
            print(Fore.YELLOW + f"\nLooking up {record_type} records for {domain}...")
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            if record_type.upper() not in record_types:
                print(Fore.RED + f"Invalid record type. Choose from: {', '.join(record_types)}")
                return None

            answers = dns.resolver.resolve(domain, record_type)
            print(Fore.GREEN + f"DNS {record_type} Records:")
            records = [rdata.to_text() for rdata in answers]
            for record in records:
                print(Fore.WHITE + f"- {record}")
            return records

        except dns.resolver.NoAnswer:
            print(Fore.YELLOW + f"No {record_type} records found")
            return None
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f"Domain {domain} does not exist")
            return None
        except dns.resolver.Timeout:
            print(Fore.RED + "DNS lookup timed out")
            return None
        except Exception as e:
            print(Fore.RED + f"DNS lookup error: {e}")
            return None

    def scrape_website(self, url):
        """Website scraper with comprehensive error handling"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"

            print(Fore.YELLOW + f"\nScraping {url}...")
            response = requests.get(url, headers=self.headers, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')

            print(Fore.GREEN + "Scraped Information:")
            print(Fore.CYAN + f"Status Code: {Fore.WHITE}{response.status_code}")
            
            if soup.title:
                print(Fore.CYAN + f"Title: {Fore.WHITE}{soup.title.string}")

            if meta_desc := soup.find('meta', attrs={'name': 'description'}):
                print(Fore.CYAN + f"Description: {Fore.WHITE}{meta_desc.get('content')}")

            links = soup.find_all('a')
            print(Fore.CYAN + f"Links Found: {Fore.WHITE}{len(links)}")
            
            return {
                'status_code': response.status_code,
                'title': soup.title.string if soup.title else None,
                'links': len(links)
            }

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"Scraping failed: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(
        description='OSINT Tool - Domain and Website Investigation',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-d', '--domain', help='Domain to investigate (e.g. example.com)')
    parser.add_argument('-u', '--url', help='URL to scrape (e.g. https://example.com)')
    parser.add_argument(
        '-r', '--records', 
        nargs='+',
        default=['A', 'MX', 'NS'],
        help='DNS record types to check (space-separated)\n'
             'Available: A, AAAA, MX, NS, TXT, CNAME'
    )
    
    args = parser.parse_args()
    tool = OSINTTool()

    if args.domain:
        tool.get_whois_info(args.domain)
        for record in args.records:
            tool.get_dns_records(args.domain, record)

    if args.url:
        tool.scrape_website(args.url)

    if not any([args.domain, args.url]):
        parser.print_help()

if __name__ == "__main__":
    print(Fore.BLUE + Style.BRIGHT + "\n=== OSINT Tool ===")
    print(Style.RESET_ALL + "Gathering public information...\n")
    main()