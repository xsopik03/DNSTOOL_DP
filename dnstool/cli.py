import argparse
import sys
from pathlib import Path

from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.ptprinthelper import ptprint

from ._version import __version__
from .config import AppConfig
from .controller import Controller
from .util.validators import is_valid_domain

OUTPUT_DIR = Path("Output")


class CliArgumentParseError(ValueError):
    pass


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliArgumentParseError(message)


def _resolve_export_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.parent == Path("."):
        return OUTPUT_DIR / path
    return path

def build_parser() -> argparse.ArgumentParser:
    parser = CliArgumentParser(add_help=False, prog="dnstool", description="dnstool <options>")
    parser.add_argument("domain", type=str, nargs="?", help="Domain name to analyze.")
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Enable JSON output.",
    )
    parser.add_argument(
        "--json-file",
        help="File to write JSON report to. Relative path is resolved under Output/."
    )
    parser.add_argument(
        "--csv-file",
        help="File to write CSV report to. Relative path is resolved under Output/."
    )
    parser.add_argument(
        "--source",
        choices=["zonemaster", "intodns", "intodns_ai", "mxtoolbox"],
        default=None,
        help="Select one source. If omitted, all sources are queried and unified.",
    )
    parser.add_argument(
        "--debug-raw",
        help="Dump the raw JSON returned by the selected source to a file."
    )
    parser.add_argument("-v", "--version", action="version", version=f"dnstool {__version__}")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")
    return parser


def run(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    
    if argv is None:
        argv = sys.argv[1:]

    json_requested = "-j" in argv or "--json" in argv
    jsonlib = ptjsonlib.PtJsonLib()
    parser = build_parser()

    if not argv or "-h" in argv or "--help" in argv:
        ptprinthelper.help_print(
            [
                {"description": ["Tool for DNS configuration analysis."]},
                {"usage": ["dnstool <domain> [options]"]},
                {"options": [
                    ["", "", "", ""],
                    ["", "", "<domain>", "Domain name to analyze"],
                    ["-j", "--json", "", "Enable JSON output"],
                    ["", "--json-file", "<file>", "Write JSON report to file (default folder: Output/)"],
                    ["", "--csv-file", "<file>", "Write CSV report to file (default folder: Output/)"],
                    ["", "--source", "<source>", "Optional source: zonemaster/intodns/intodns_ai/mxtoolbox (omit to use all)"],
                    ["", "--debug-raw", "<file>", "Dump raw source response"],
                    ["-v", "--version", "", "Show script version and exit"],
                    ["-h", "--help", "", "Show this help message and exit"],
                ]},
            ],
            "dnstool",
            __version__,
        )
        return 0

    try:
        args = parser.parse_args(argv)
    except CliArgumentParseError as exc:
        if json_requested:
            jsonlib.end_error(f"Argument error: {exc}", True)
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2

    ptprinthelper.print_banner("dnstool", __version__, args.json)

    if not args.domain:
        jsonlib.end_error("Domain argument is required.", args.json)
        return 1

    domain = args.domain.strip().lower()
    if not is_valid_domain(domain):
        jsonlib.end_error(f"'{domain}' is not a valid domain name.", args.json)
        return 1
    
    json_file = None
    csv_file = None
    debug_file = None

    try:
        config = AppConfig.from_env()
        controller = Controller(config=config, jsonlib=jsonlib, json_mode=args.json)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        if args.json_file:
            json_output_path = _resolve_export_path(args.json_file)
            json_output_path.parent.mkdir(parents=True, exist_ok=True)
            json_file = open(json_output_path, "w", encoding="utf-8")
        if args.csv_file:
            csv_output_path = _resolve_export_path(args.csv_file)
            csv_output_path.parent.mkdir(parents=True, exist_ok=True)
            csv_file = open(csv_output_path, "w", encoding="utf-8", newline="")
        if args.debug_raw:
            debug_file = open(args.debug_raw, "w", encoding="utf-8")

        controller.run_analysis(
            domain=domain,
            source=args.source,
            json_file=json_file,
            csv_file=csv_file,
            debug_raw_output_file=debug_file,
        )
    except Exception as exc:
        jsonlib.end_error(f"Unexpected error: {exc}", args.json)
        return 1
    finally:
        if json_file and not json_file.closed:
            json_file.close()
        if csv_file and not csv_file.closed:
            csv_file.close()
        if debug_file and not debug_file.closed:
            debug_file.close()

    ptprint(jsonlib.get_result_json(), "", args.json)
        
    return 0