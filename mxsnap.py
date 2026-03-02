import sys
import os
import time
import json
import csv
import shutil
import argparse
import dns.resolver

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

BANNER = (
    "\n"
    f"  {CYAN}\u2588\u2584 \u2584\u2588 \u2580\u2584\u2580 {WHITE}\u2588\u2580 \u2588\u2584 \u2588 \u2584\u2580\u2588 \u2588\u2580\u2588\n"
    f"  {CYAN}\u2588 \u2580 \u2588 \u2588 \u2588 {WHITE}\u2584\u2588 \u2588 \u2580\u2588 \u2588\u2580\u2588 \u2588\u2580\u2580{RESET}\n"
)

KNOWN_PROVIDERS = {
    "google": "Google Workspace",
    "googlemail": "Google Workspace",
    "outlook": "Microsoft 365",
    "microsoft": "Microsoft 365",
    "protonmail": "ProtonMail",
    "proton": "ProtonMail",
    "zoho": "Zoho Mail",
    "icloud": "Apple iCloud",
    "yahoodns": "Yahoo Mail",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "pphosted": "Proofpoint",
    "securemx": "Proofpoint",
    "messagelabs": "Broadcom/Symantec",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "postmark": "Postmark",
    "amazonaws": "Amazon SES",
    "ovh": "OVH",
    "ionos": "IONOS",
    "strato": "Strato",
    "hetzner": "Hetzner",
    "fastmail": "Fastmail",
    "tutanota": "Tuta",
    "tuta": "Tuta",
    "migadu": "Migadu",
    "mailcheap": "Mailcheap",
    "sophos": "Sophos",
    "forcepoint": "Forcepoint",
}

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "k3", "s1", "s2", "dkim", "mail",
    "smtp", "mandrill", "mailgun", "postmark",
    "pm", "protonmail", "everlytickey1", "everlytickey2",
    "cm", "turbo-smtp"
]


def loading_bar():
    width = min(shutil.get_terminal_size().columns - 10, 40)
    block = "\u2588"
    empty = "\u2591"
    for i in range(width + 1):
        bar = block * i + empty * (width - i)
        print(f"\r  {CYAN}{bar}{RESET}", end="", flush=True)
        time.sleep(0.02)
    print()


def detect_provider(mx_host):
    mx_lower = mx_host.lower()
    for keyword, name in KNOWN_PROVIDERS.items():
        if keyword in mx_lower:
            return name
    return None


def lookup_mx(domain):
    results = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for rdata in sorted(answers, key=lambda r: r.preference):
            host = str(rdata.exchange).rstrip(".")
            provider = detect_provider(host)
            entry = {
                "priority": rdata.preference,
                "host": host,
                "provider": provider
            }
            results.append(entry)

            provider_str = f"  {YELLOW}{provider}{RESET}" if provider else ""
            print(f"  {GREEN}{rdata.preference:>5}{RESET}  {host}{provider_str}")
    except dns.resolver.NoAnswer:
        print(f"  {RED}No MX records found.{RESET}")
    except dns.resolver.NXDOMAIN:
        print(f"  {RED}Domain does not exist.{RESET}")
    except dns.resolver.NoNameservers:
        print(f"  {RED}No nameservers available.{RESET}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    return results


# === FEATURE: --spf ===
def check_spf(domain):
    print(f"\n  {BOLD}SPF Record{RESET}\n")
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                print(f"  {GREEN}{txt}{RESET}")

                issues = []
                if "+all" in txt:
                    issues.append("'+all' allows anyone to send as this domain")
                if "~all" in txt:
                    issues.append("'~all' soft fail - spoofed mail may still be delivered")
                if "-all" not in txt and "~all" not in txt and "?all" not in txt:
                    issues.append("No 'all' mechanism - no policy for unauthorized senders")

                if issues:
                    print()
                    for issue in issues:
                        print(f"    {YELLOW}> {issue}{RESET}")
                elif "-all" in txt:
                    print(f"\n    {GREEN}> Strict policy (-all) - good{RESET}")

                return txt
        print(f"  {RED}No SPF record found.{RESET}")
    except dns.resolver.NoAnswer:
        print(f"  {RED}No TXT records found.{RESET}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    return None


# === FEATURE: --dmarc ===
def check_dmarc(domain):
    print(f"\n  {BOLD}DMARC Record{RESET}\n")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=DMARC1" in txt:
                print(f"  {GREEN}{txt}{RESET}")

                issues = []
                if "p=none" in txt:
                    issues.append("'p=none' - no enforcement, only monitoring")
                elif "p=quarantine" in txt:
                    issues.append("'p=quarantine' - suspicious mail goes to spam")
                elif "p=reject" in txt:
                    issues.append("'p=reject' - strict enforcement - good")

                if "rua=" not in txt:
                    issues.append("No 'rua' tag - no aggregate reports configured")

                if issues:
                    print()
                    for issue in issues:
                        color = GREEN if "good" in issue else YELLOW
                        print(f"    {color}> {issue}{RESET}")

                return txt
        print(f"  {RED}No DMARC record found.{RESET}")
    except dns.resolver.NXDOMAIN:
        print(f"  {RED}No DMARC record found.{RESET}")
    except dns.resolver.NoAnswer:
        print(f"  {RED}No DMARC record found.{RESET}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    return None


# === FEATURE: --dkim ===
def check_dkim(domain):
    print(f"\n  {BOLD}DKIM Records{RESET}\n")
    found = []
    for selector in DKIM_SELECTORS:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                print(f"  {GREEN}{selector}{RESET}  {DIM}{txt[:80]}{'...' if len(txt) > 80 else ''}{RESET}")
                found.append({"selector": selector, "record": txt})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

    if not found:
        print(f"  {YELLOW}No DKIM records found for common selectors.{RESET}")
    return found


# === FEATURE: --export ===
def export_results(data, fmt, domain):
    filename = f"mxsnap_{domain}.{fmt}"
    if fmt == "json":
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
    elif fmt == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "value", "extra"])
            for mx in data.get("mx_records", []):
                writer.writerow(["mx", mx["host"], f"priority={mx['priority']} provider={mx.get('provider', '')}"])
            if data.get("spf"):
                writer.writerow(["spf", data["spf"], ""])
            if data.get("dmarc"):
                writer.writerow(["dmarc", data["dmarc"], ""])
            for d in data.get("dkim", []):
                writer.writerow(["dkim", d["selector"], d["record"]])
    print(f"\n  {GREEN}Exported: {filename}{RESET}")


def scan_domain(domain, args):
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    print(f"\n  {DIM}{domain}{RESET}\n")
    loading_bar()
    print(f"\n  {BOLD}MX Records{RESET}\n")

    export_data = {
        "domain": domain,
        "mx_records": [],
        "spf": None,
        "dmarc": None,
        "dkim": []
    }

    export_data["mx_records"] = lookup_mx(domain)

    if args.spf or args.all:
        export_data["spf"] = check_spf(domain)

    if args.dmarc or args.all:
        export_data["dmarc"] = check_dmarc(domain)

    if args.dkim or args.all:
        export_data["dkim"] = check_dkim(domain)

    if args.export:
        export_results(export_data, args.export, domain)

    print()


def parse_inline(raw):
    parts = raw.split()
    domain = parts[0]
    inline_args = argparse.Namespace(
        domain=domain,
        spf=False,
        dmarc=False,
        dkim=False,
        all=False,
        export=None,
        bulk=None,
        help=False
    )
    i = 1
    while i < len(parts):
        flag = parts[i]
        if flag == "--spf":
            inline_args.spf = True
        elif flag == "--dmarc":
            inline_args.dmarc = True
        elif flag == "--dkim":
            inline_args.dkim = True
        elif flag == "--all":
            inline_args.all = True
        elif flag == "--export" and i + 1 < len(parts):
            i += 1
            if parts[i] in ("json", "csv"):
                inline_args.export = parts[i]
        i += 1
    return domain, inline_args


def interactive_mode(args):
    print(f"\n  {DIM}Enter a domain or 'exit' to quit{RESET}")
    print(f"  {DIM}Flags can be added inline: example.com --all{RESET}")
    while True:
        try:
            raw = input(f"\n  {CYAN}>{RESET} ").strip()
            if raw.lower() in ("exit", "quit", "q"):
                break
            if raw:
                if " " in raw:
                    domain, inline_args = parse_inline(raw)
                    scan_domain(domain, inline_args)
                else:
                    scan_domain(raw, args)
        except (KeyboardInterrupt, EOFError):
            print()
            break


def get_active_flags(args):
    flags = []
    if args.spf:
        flags.append("--spf")
    if args.dmarc:
        flags.append("--dmarc")
    if args.dkim:
        flags.append("--dkim")
    if args.all:
        flags.append("--all")
    if args.export:
        flags.append(f"--export {args.export}")
    if args.bulk:
        flags.append(f"--bulk {args.bulk}")
    return flags


def main():
    parser = argparse.ArgumentParser(
        description="MXSnap - MX Record Lookup Tool",
        add_help=False
    )
    parser.add_argument("domain", nargs="?", default=None)
    parser.add_argument("--spf", action="store_true",
                        help="Check SPF record")
    parser.add_argument("--dmarc", action="store_true",
                        help="Check DMARC record")
    parser.add_argument("--dkim", action="store_true",
                        help="Check DKIM records (common selectors)")
    parser.add_argument("--all", action="store_true",
                        help="Enable all checks")
    parser.add_argument("--export", choices=["json", "csv"], default=None,
                        help="Export results (json or csv)")
    parser.add_argument("--bulk", default=None,
                        help="File with domains (one per line)")
    parser.add_argument("-h", "--help", action="store_true")

    args = parser.parse_args()

    print(BANNER)

    if args.help:
        print(__doc__)
        return

    if args.bulk:
        if not os.path.isfile(args.bulk):
            print(f"  {RED}File not found: {args.bulk}{RESET}")
            return
        with open(args.bulk) as f:
            domains = [line.strip() for line in f if line.strip()]
        print(f"  {BOLD}{len(domains)} domains loaded{RESET}\n")
        for domain in domains:
            scan_domain(domain, args)
        return

    if args.domain:
        scan_domain(args.domain, args)
    else:
        interactive_mode(args)


if __name__ == "__main__":
    main()