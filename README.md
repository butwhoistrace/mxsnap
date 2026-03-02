# MXSnap

Fast MX record lookup tool for the command line.

## Installation

```
git clone https://github.com/butwhoistrace/mxsnap
cd mxsnap
pip install dnspython
```

## Usage

```
python3 mxsnap.py <domain>
python3 mxsnap.py                          # Interactive mode
```

## Optional Flags

| Flag | Description |
|------|-------------|
| `--spf` | Check SPF record and analyze policy |
| `--dmarc` | Check DMARC record and analyze enforcement |
| `--dkim` | Check DKIM records across common selectors |
| `--all` | Enable all checks |
| `--export json` | Export results as JSON |
| `--export csv` | Export results as CSV |
| `--bulk domains.txt` | Scan multiple domains from file |

Flags can be combined:

```
python3 mxsnap.py example.com --spf --dmarc --dkim --export json
```

## What It Checks

**MX Records** - Mail servers and their priority, auto-detects known providers (Google Workspace, Microsoft 365, ProtonMail etc.)

**SPF** - Validates sender policy and warns about weak configurations like `+all` or missing `all` mechanism.

**DMARC** - Checks enforcement policy (`none`, `quarantine`, `reject`) and whether aggregate reporting is configured.

**DKIM** - Scans 20+ common selectors (`default`, `google`, `selector1`, `selector2`, `k1`, `mail` etc.) for published keys.

## Bulk Scan

Create a text file with one domain per line:

```
example.com
github.com
stackoverflow.com
```

```
python3 mxsnap.py --bulk domains.txt --all --export csv
```

## Disclaimer

This tool only queries publicly accessible DNS records. Use responsibly.
