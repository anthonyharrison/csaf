# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: MIT

import json
import textwrap
from pathlib import Path


class CSAFAnalyser:

    TAB = "\t\t"
    def __init__(self, filename):
        self.filename = filename
        # Check file exists
        invalid_file = True
        if len(self.filename) > 0:
            # Check path
            filePath = Path(self.filename)
            # Check path exists and is a valid file
            if filePath.exists() and filePath.is_file():
                # Assume that processing can proceed
                invalid_file = False
        if invalid_file:
            raise FileNotFoundError
        self.data = json.load(open(self.filename))
        self.product_list = {}

    def validate(self):
        # Does this document look like a CSAF document?
        if (
            "document" in self.data
            and "product_tree" in self.data
            and "vulnerabilities" in self.data
        ):
            return True
        return False

    def _process_branch_element(self, branch_element, element):
        category = branch_element.get("category", None)
        name = branch_element.get("name", None)
        if category is not None:
            element[category] = name
        return element

    def _process_branch(self, branch_element, element):
        element = self._process_branch_element(branch_element, element)
        if "branches" in branch_element:
            for branch in branch_element["branches"]:
                element = self._process_branch(branch, element)
                if "product" in branch:
                    element["product_id"] = branch["product"]["product_id"]
                    item = {}
                    item["vendor"] = element.get("vendor", None)
                    item["product"] = element.get("product_name", None)
                    item["version"] = element.get("product_version", None)
                    if item["version"] is None:
                        item["version"] = element.get("product_version_range", None)
                    item["family"] = element.get("product_family", None)
                    id = element.get("product_id", None)
                    if id is not None and id not in self.product_list:
                        self.product_list[id] = item
        return element

    def _heading(self, title, level = 1):
        line_char = "=" if level == 1 else "-"
        line = line_char*len(title)
        print(f"\n{title}\n{line}\n")

    def _print(self, attribute, information, separator = True):
        sep = ":" if separator else " "
        print(f"{attribute:40} {sep} {information.strip()}")

    def _multiline(self, attribute, text_field):
        MAX_NOTE_LENGTH = 100
        title_line = True
        output_lines = textwrap.wrap(text_field, width=MAX_NOTE_LENGTH)
        for output in output_lines:
            if title_line:
                self._print(attribute, output)
                title_line = False
            else:
                self._print(" ", output, separator=False)

    def _show_product(self, product_entry, vendor = True, tab = False):
        tab = self.TAB if tab else ""
        if product_entry['product'] is not None and product_entry['vendor'] is not None and product_entry['version'] is not None:
            if vendor:
                print(
                    f"{tab}{product_entry['product']:30} {product_entry['vendor']:30} {product_entry['version']}"
                )
            else:
                print(
                    f"{tab}{product_entry['product']:30} {product_entry['version']}"
                )
    def _show_product_list(self, product_list):
        if len(product_list) > 0:
            print("\nProduct                        Vendor                         Release")
            print("-" * 90)
            for entry in product_list:
                self._show_product(product_list[entry])

    def _show_product_id(self, product_ids):
        if len(product_ids) > 0:
            print(f"\n{self.TAB}Product                        Release")
            print(f"{self.TAB}{'-' * 60}")
            for entry in product_ids:
                self._show_product(self.product_list[entry], vendor=False, tab=True)

    def analyse(self):
        # Abort analysis if not a valid CSAF document
        if not self.validate():
            print(f"[ERROR] {self.filename} is not a valid CSAF document")
            return

        # Key attributes from the CSAF header
        self._heading("Header")
        self._print("CSAF Version", self.data["document"]["csaf_version"])
        self._print("Title", self.data["document"]["title"])
        self._print("Date", self.data["document"]["tracking"]["current_release_date"])
        if "notes" in self.data["document"]:
            for note in self.data["document"]["notes"]:
                # Notes can be multi-line. Split text up across multiple lines
                self._multiline(note["title"], note["text"])
        if "publisher" in self.data["document"]:
            publisher_info = (
                f"{self.data['document']['publisher']['name']} "
                f"{self.data['document']['publisher']['namespace']}"
            )
            self._print("Publisher", publisher_info)
        if "tracking" in self.data["document"]:
            if "generator" in self.data["document"]["tracking"]:
                generator_version = "UNKNOWN"
                if "version" in self.data["document"]["tracking"]["generator"]["engine"]:
                    generator_version = self.data["document"]["tracking"]["generator"]["engine"]["version"]
                self._print(
                    "Generator",
                    f"{self.data['document']['tracking']['generator']['engine']['name']} "
                    f"version {generator_version}",
                )
            self._print("Id", self.data["document"]["tracking"]["id"])
            if "revision_history" in self.data["document"]["tracking"]:
                for revision in self.data["document"]["tracking"]["revision_history"]:
                    self._multiline(f"Revision {revision['number']} {revision['date']}", revision['summary'])
            self._print("Status", self.data["document"]["tracking"]["status"])
            self._print("Version", self.data["document"]["tracking"]["version"])
        if "references" in self.data["document"]:
            for reference in self.data["document"]["references"]:
                category = ""
                if "category" in reference:
                    if reference['category'] == "external":
                        category = "(External)"
                self._multiline(f"Reference {category}", reference['summary'])
                self._print("", reference['url'], separator=False)
        if "distribution" in self.data["document"]:
            distribution_info = ""
            if "text" in self.data['document']['distribution']:
                distribution_info = (
                    f"{self.data['document']['distribution']['text']}")
            if "tlp" in self.data['document']['distribution']:
                distribution_info = distribution_info + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
            self._print("Distribution", distribution_info)
        #
        # Show product tree
        #
        self._heading("Product Tree")
        for d in self.data["product_tree"]["branches"]:
            element = {}
            element = self._process_branch(d, element)

        self._show_product_list(self.product_list)
        #
        # Show vulnerabilities
        #
        self._heading("Vulnerabilities")
        for d in self.data["vulnerabilities"]:
            print ("\n")
            if "title" in d:
                self._print("Title", d['title'] )
            self._print("CVE ID", d['cve'])
            if "notes" in d:
                for note in d['notes']:
                    self._multiline(note['title'], note['text'])
            if "discovery_date" in d:
                self._print("Discovery Date", d['discovery_date'] )
            if "ids" in d:
                for id in d['ids']:
                    self._print (id['system_name'], id['text'])
            if "product_status" in d:
                for product_status in d["product_status"]:
                    self._print(product_status.upper(),"")
                    self._show_product_id(d["product_status"][product_status])
            if "references" in d:
                for reference in d["references"]:
                    category = ""
                    if "category" in reference:
                        if reference['category'] == "external":
                            category = "(External)"
                    self._multiline(f"Reference {category}", reference['summary'])
                    self._print("", reference['url'], separator=False)
            if "release_date" in d:
                self._print("Release Date", d['release_date'] )
            if "remediations" in d:
                self._heading("Remediations", level=2)
                for remediation in d["remediations"]:
                    fix = remediation["category"].upper()
                    details = remediation["details"]
                    self._multiline(fix, details)
                    if "product_ids" in remediation:
                        self._show_product_id(remediation["product_ids"])
                        print ("\n")
            if "threats" in d:
                for threat in d["threats"]:
                    self._print(threat['category'], threat['details'])
            print (f"\n{'#' * 140}")

if __name__ == "__main__":
    csaf_filename = "test_csaf.json"
    csaf = CSAFAnalyser(csaf_filename)
    print(f"{csaf_filename} a valid CSAF document : {csaf.validate()}")
    csaf.analyse()
