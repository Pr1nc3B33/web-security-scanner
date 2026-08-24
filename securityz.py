import argparse

from cybertruckz.scanner import run_all_checks
from cybertruckz.report import format_report, generate_pdf_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan a website for common security misconfigurations."
    )
    parser.add_argument("url", help="The URL to scan, e.g. https://example.com")
    parser.add_argument("--pdf", action="store_true", help="Also generate a branded PDF report.")

    args = parser.parse_args()

    findings = run_all_checks(args.url)
    print(format_report(args.url, findings))

    if args.pdf:
        filename = generate_pdf_report(args.url, findings)
        print(f"\nPDF report saved to: {filename}")