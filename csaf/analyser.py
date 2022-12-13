# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: MIT

import json
from pathlib import Path


class CSAFAnalyser:
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
                    id = element.get("product_id", None)
                    if id is not None and id not in self.product_list:
                        self.product_list[id] = item
        return element

    def _heading(self, title):
        line = "="*len(title)
        print(f"{title}\n{line}\n")

    def _print(self, attribute, information):
        print(f"{attribute:40} : {information.strip()}")

    def _multiline(self, attribute, text_field):
        MAX_NOTE_LENGTH = 100
        text_detail = text_field.replace("\n", " ").replace("\r", "").replace("  ", " ")
        title_line = True
        while len(text_detail) > 0:
            text_info = text_detail[:MAX_NOTE_LENGTH].lstrip()
            if title_line:
                self._print(attribute, text_info)
                title_line = False
            else:
                self._print(" ", text_info)
            text_detail = text_detail[MAX_NOTE_LENGTH:]

    def _show_product(self, product_entry):
        if product_entry['product'] is not None and product_entry['vendor'] is not None and product_entry['version'] is not None:
            print(
                f"{product_entry['product']:30} {product_entry['vendor']:30} {product_entry['version']}"
            )

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
                self._print("", reference['url'])
        if "distribution" in self.data["document"]:
            distribution_info = (
                f"{self.data['document']['distribution']['text']}")
            if "tlp" in self.data['document']['distribution']:
                distribution_info = distribution_info + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
            self._print("Distribution", distribution_info)
        # Show product tree
        self._heading("Product Tree")
        for d in self.data["product_tree"]["branches"]:
            element = {}
            element = self._process_branch(d, element)

        print("Product                        Vendor                         Release")
        print("-" * 90)
        for entry in self.product_list:
            self._show_product(self.product_list[entry])

        self._heading("Vulnerabilities")
        for d in self.data["vulnerabilities"]:
            if "note" in d:
                print(f"\n{d['cve']} {d['note']['text']}")
            else:
                print(f"\n{d['cve']}")
            if "product_status" in d and "known_affected" in d["product_status"]:
                for p in d["product_status"]["known_affected"]:
                    if p in self.product_list:
                        self._show_product(self.product_list[p])
                    else:
                        # Just show product ID
                        print(f"Product: {p:30} ")
            if "recommendation" in d:
                fix = d["recommendation"]["category"]
                details = d["recommendation"]["details"]
                self._multiline(fix, details)
                if "product_ids" in d:
                    for p in d["recommendation"]["product_ids"]:
                        if p in self.product_list:
                            self._show_product(self.product_list[p])
                        else:
                            print(f"Product Id: {p}")
            if "remediations" in d:
                for remediation in d["remediations"]:
                    fix = remediation["category"]
                    details = remediation["details"]
                    self._multiline(fix, details)
                    if "product_ids" in remediation:
                        for p in remediation["product_ids"]:
                            if p in self.product_list:
                                self._show_product(self.product_list[p])
                            else:
                                print(f"Product Id: {p}")

if __name__ == "__main__":
    csaf_filename = "test_csaf.json"
    csaf = CSAFAnalyser(csaf_filename)
    print(f"{csaf_filename} a valid CSAF document : {csaf.validate()}")
    csaf.analyse()
