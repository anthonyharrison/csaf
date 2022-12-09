# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: MIT

import argparse
import csv
import sys
import textwrap
from collections import ChainMap
from pathlib import Path

from csaf.analyser import CSAFAnalyser
from csaf.generator import CSAFGenerator
from csaf.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "csaf-tool"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            CSAF-tool generates a CSAF 2.0 file including product tree and
            vulnerabilities associated with products specified in the
            product tree.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-g",
        "--generate",
        action="store_true",
        default=False,
        help="generate CSAF file",
    )
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="CSAF filename to be analysed",
    )
    input_group.add_argument(
        "-p",
        "--product",
        action="store",
        default="",
        help="product tree",
    )
    input_group.add_argument(
        "-v",
        "--vulnerabilities",
        action="store",
        default="",
        help="list of vulnerabilities",
    )
    input_group.add_argument(
        "-t",
        "--title",
        action="store",
        default="",
        help="CSAF title",
    )
    input_group.add_argument(
        "--header",
        action="store",
        default="",
        help="CSAF heading",
    )
    input_group.add_argument(
        "--id",
        action="store",
        default="",
        help="CSAF document identifier",
    )
    parser.add_argument(
        "-C", "--config", action="store", default="", help="name of config file"
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="CSAF filename",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "output_file": "",
        "generate": False,
        "product": "",
        "vulnerabilities": "",
        "title": "",
        "header": "",
        "id": "",
        "config": "",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    cli_error = False
    if args["generate"]:
        # Need an output filename specified
        if args["output_file"] == "":
            print("[ERROR] CSAF output filename not specified")
            cli_error = True
        # Need product tree and set of vulnerabilities
        if args["product"] == "":
            print("[ERROR] Product tree filename not specified")
            cli_error = True
        else:
            # Check file exists
            filePath = Path(args["product"])
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                pass
            else:
                print(f"[ERROR] Product filename {args['product']} not found")
                cli_error = True
        if args["vulnerabilities"] == "":
            print("[ERROR] Vulnerabilties filename not specified")
            cli_error = True
        else:
            # Check file exists
            filePath = Path(args["vulnerabilities"])
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                pass
            else:
                print(
                    f"[ERROR] Vulnerabilties filename {args['vulnerabilities']} not found"
                )
                cli_error = True
    else:
        # Assume analysis
        # Need an input file
        if args["input_file"] == "":
            print("[ERROR] CSAF filename not specified")
            cli_error = True

    # Exit if any error detected with CLI parameters
    if cli_error:
        return -1

    if args["generate"]:
        csaf_gen = CSAFGenerator(args["config"])
        csaf_gen.set_title(args["title"])
        csaf_gen.set_header_title(args["header"])
        csaf_gen.set_id(args["id"])
        # Process product tree file
        with open(args["product"]) as csv_file:
            product_data = csv.DictReader(csv_file)
            if product_data is None or product_data.fieldnames is None:
                print("[ERROR] Unable to process product tree")
            else:
                for data in product_data:
                    csaf_gen.add_product(
                        product_name=data["product"],
                        vendor=data["vendor"],
                        release=data["release"],
                    )

        # Process vulnerabilities file
        with open(args["vulnerabilities"]) as csv_file:
            vuln_data = csv.DictReader(csv_file)
            if vuln_data is None or vuln_data.fieldnames is None:
                print("[ERROR] Unable to process vulnerability data")
            else:
                for data in vuln_data:
                    csaf_gen.add_vulnerability(
                        product_name=data["product"],
                        release=data["release"],
                        id=data["id"],
                        description=data["description"],
                        status=data["status"],
                        comment=data["comment"],
                    )

        csaf_gen.generate_csaf()
        csaf_gen.publish_csaf(args["output_file"])

    elif args["input_file"]:
        try:
            csaf = CSAFAnalyser(args["input_file"])
            csaf.analyse()
        except FileNotFoundError:
            print("[ERROR] CSAF filename not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
