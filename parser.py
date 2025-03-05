from argparse import ArgumentParser
from os import path
from pathlib import Path
from colorama import Fore, Style

parser = ArgumentParser(
        prog='bulk_scanner.py',
        description =Fore.GREEN + 'IoC Scanner Using VirusTotal and AbuseIPDB API in Python (Supports Excel Files Only)' + Style.RESET_ALL,
        epilog='Simple Python script for SOC Analyst'
    )

input_group = parser.add_argument_group("Input Options")
input_group.add_argument("file", type=str, help="Specify the input Excel file")
input_group.add_argument("--sheet", type=int, help="Specify the Sheet Number (default: 0)")
input_group.add_argument("--column", type=str, help="Specify the column to extract data from (default: A)")

output_group = parser.add_argument_group("Output Options")
output_group.add_argument("--append", action="store_true", help="Append to existing Excel file (default: False)")

args = parser.parse_args()

if args.append:
    if not path.isabs(args.file): 
        parser.error(Fore.RED + "Use an absolute file path for --append.")

if args.file:
    if not path.exists(args.file):
        parser.error(Fore.RED + "The specified file does not exist. Please provide a valid file path.")
    
    extension = Path(args.file).suffix
    if extension not in [".xlsx", ".xls", ".xlsb", ".xltx"]:
        parser.error(Fore.RED + "The specified file is not a valid Excel file.")