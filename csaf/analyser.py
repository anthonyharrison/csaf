# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: MIT

import json
import textwrap
from pathlib import Path

from packageurl import PackageURL
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


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
                    if "product_identification_helper" in branch["product"]:
                        pid = branch["product"]["product_identification_helper"]
                        if "cpe" in pid:
                            cpe_info = pid["cpe"]
                            cpe_items = cpe_info.split(":")
                            if cpe_items[1] == "/a":
                                # Example is cpe:/a:redhat:rhel_eus:8.2::realtime
                                element["product_version"] = cpe_items[4]
                            elif cpe_items[1] == "2.3":
                                # Example is cpe:2.3:a:redhat:rhel_eus:8.2::realtime
                                element["product_version"] = cpe_items[5]
                        elif "purl" in pid:
                            purl_info = PackageURL.from_string(pid["purl"])
                            element["product_version"] = purl_info.to_dict()["version"]
                    item = {}
                    item["vendor"] = element.get("vendor", None)
                    item["product"] = element.get("product_name", "Not defined")
                    item["version"] = element.get("product_version", None)
                    if item["version"] is None:
                        item["version"] = element.get("product_version_range", None)
                    item["family"] = element.get("product_family", "")
                    id = element.get("product_id", None)
                    if id is not None and id not in self.product_list:
                        item["id"] = id
                        self.product_list[id] = item
                    # element = {}
        return element

    def _heading(self, title, level=1, rich=False):
        if level == 1:
            print(Panel(title.upper(), style="bold"))
        else:
            line_char = "-"
            line = line_char * len(title)
            print(f"\n{title}\n{line}\n")
        self.rich = rich
        if self.rich:
            self.table = Table()
            self.table.add_column("Item")
            self.table.add_column("Details")

    def _print(self, attribute, information, separator=True):
        sep = ":" if separator else " "
        if not self.rich:
            print(f"{attribute:40} {sep} {information.strip()}")
        else:
            self.table.add_row(attribute, information.strip())

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

    def _show_product_list(self, product_list):
        if len(product_list) > 0:
            table = Table()
            table.add_column("Id")
            table.add_column("Family")
            table.add_column("Product")
            table.add_column("Vendor")
            table.add_column("Release")
            shown = []
            for entry in product_list:
                product_entry = product_list[entry]
                if product_entry not in shown:
                    table.add_row(
                        product_entry["id"],
                        product_entry["family"],
                        product_entry["product"],
                        product_entry["vendor"],
                        product_entry["version"],
                    )
                    shown.append(product_entry)
            self.console.print(table)

    def _show_product_id(self, product_ids):
        if len(product_ids) > 0:
            table = Table()
            table.add_column("Product")
            table.add_column("Release")
            shown = []
            for entry in product_ids:
                product_entry = self.product_list[entry]
                if product_entry not in shown:
                    table.add_row(product_entry["product"], product_entry["version"])
                    shown.append(product_entry)
            self.console.print(table)

    def analyse(self):
        # Abort analysis if not a valid CSAF document
        if not self.validate():
            print(f"[ERROR] {self.filename} is not a valid CSAF document")
            return
        self.console = Console()
        # Key attributes from the CSAF header
        self._heading("CSAF Header", rich=True)
        self._print("CSAF Version", self.data["document"]["csaf_version"])
        self._print("Title", self.data["document"]["title"])
        self._print("Category", self.data["document"]["category"])
        self._print("Date", self.data["document"]["tracking"]["current_release_date"])
        if "aggregate_severity" in self.data["document"]:
            self._print("Severity", self.data["document"]["aggregate_severity"]["text"])
        if "notes" in self.data["document"]:
            for note in self.data["document"]["notes"]:
                # Notes can be multi-line. Split text up across multiple lines
                # category and text are mandatory.
                if "title" not in note:
                    self._multiline(note["category"],note["text"])
                else:
                    self._multiline(note["title"], note["text"])
        if "publisher" in self.data["document"]:
            publisher_info = (
                f"{self.data['document']['publisher']['name']} "
                f"{self.data['document']['publisher']['namespace']}"
            )
            self._print("Publisher", publisher_info)
            if "contact_details" in self.data['document']['publisher']:
                self._print("Contact Details", self.data['document']['publisher']['contact_details'])
        if "tracking" in self.data["document"]:
            if "generator" in self.data["document"]["tracking"]:
                generator_version = "UNKNOWN"
                if (
                    "version"
                    in self.data["document"]["tracking"]["generator"]["engine"]
                ):
                    generator_version = self.data["document"]["tracking"]["generator"][
                        "engine"
                    ]["version"]
                self._print(
                    "Generator",
                    f"{self.data['document']['tracking']['generator']['engine']['name']} "
                    f"version {generator_version}",
                )
            self._print("Id", self.data["document"]["tracking"]["id"])
            if "revision_history" in self.data["document"]["tracking"]:
                for revision in self.data["document"]["tracking"]["revision_history"]:
                    self._multiline(
                        f"Revision {revision['number']} {revision['date']}",
                        revision["summary"],
                    )
            self._print("Status", self.data["document"]["tracking"]["status"])
            self._print("Version", self.data["document"]["tracking"]["version"])
        if "references" in self.data["document"]:
            for reference in self.data["document"]["references"]:
                category = ""
                if "category" in reference:
                    if reference["category"] == "external":
                        category = "(External)"
                self._multiline(f"Reference {category}", reference["summary"])
                self._print("", reference["url"], separator=False)
        if "distribution" in self.data["document"]:
            distribution_info = ""
            if "text" in self.data["document"]["distribution"]:
                distribution_info = f"{self.data['document']['distribution']['text']}"
            if "tlp" in self.data["document"]["distribution"]:
                distribution_info = (
                    distribution_info
                    + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
                )
            self._print("Distribution", distribution_info)

        self.console.print(self.table)
        #
        # Show product tree
        #
        self._heading("Product Tree")
        for d in self.data["product_tree"]["branches"]:
            element = {}
            element = self._process_branch(d, element)

        if "relationships" in self.data["product_tree"]:
            for relation in self.data["product_tree"]["relationships"]:
                product_id = relation["full_product_name"]["product_id"]
                product_ref = relation["product_reference"]
                relates_to = relation["relates_to_product_reference"]
                item = self.product_list[relates_to]
                self.product_list[product_ref] = item
                if product_id not in self.product_list:
                    self.product_list[product_id] = item

        self._show_product_list(self.product_list)
        #
        # Show vulnerabilities
        #
        self._heading("Vulnerabilities")
        for d in self.data["vulnerabilities"]:
            self._heading("Vulnerability " + d["cve"], rich=True)
            if "title" in d:
                self._print("Title", d["title"])
            self._print("CVE ID", d["cve"])
            if "cwe" in d:
                self._print("CWE", f"{d['cwe']['id']} - {d['cwe']['name']}")
            if "notes" in d:
                for note in d["notes"]:
                    if "title" in note:
                        if note["text"] is not None:
                            self._multiline(note["title"], note["text"])
                        else:
                            self._multiline(note["title"], "")
                    else:
                        self._multiline(note["category"], note.get("text",""))
            if "discovery_date" in d:
                self._print("Discovery Date", d["discovery_date"])
            if "flags" in d:
                for flag in d["flags"]:
                    if "label" in flag:
                        self._print("Exploitation", flag["label"])
                    for product in flag["product_ids"]:
                        self._print("Product", product)
            if "ids" in d:
                for id in d["ids"]:
                    self._print(id["system_name"], id["text"])
            if "references" in d:
                for reference in d["references"]:
                    category = ""
                    if "category" in reference:
                        if reference["category"] == "external":
                            category = "(External)"
                    self._multiline(f"Reference {category}", reference["summary"])
                    self._print("", reference["url"], separator=False)
            if "release_date" in d:
                self._print("Release Date", d["release_date"])
            if "threats" in d:
                for threat in d["threats"]:
                    self._print(threat["category"], threat["details"])
            if "scores" in d:
                for score in d["scores"]:
                    if "cvss_v3" in score:
                        self._print(
                            "CVSS3 Score",
                            str(score["cvss_v3"]["baseScore"])
                            + " ("
                            + score["cvss_v3"]["baseSeverity"]
                            + ")",
                        )
                        self._print("CVSS3 Vector", score["cvss_v3"]["vectorString"])
                    elif "cvss_v2" in score:
                        self._print(
                            "CVSS2 Score",
                            str(score["cvss_v2"]["baseScore"])
                            + " ("
                            + score["cvss_v2"]["baseSeverity"]
                            + ")",
                        )
                        self._print("CVSS22 Vector", score["cvss_v2"]["vectorString"])
            self.console.print(self.table)
            self.rich = False
            if "scores" in d:
                for score in d["scores"]:
                    if "products" in score:
                        self._heading("PRODUCTS", level=2)
                        self._show_product_id(score["products"])
            if "product_status" in d:
                for product_status in d["product_status"]:
                    self._heading(product_status.upper(), level=2)
                    self._show_product_id(d["product_status"][product_status])
            if "remediations" in d:
                self._heading("Remediations", level=2)
                for remediation in d["remediations"]:
                    fix = remediation["category"].upper()
                    details = remediation["details"]
                    self._multiline(fix, details)
                    if "product_ids" in remediation:
                        self._show_product_id(remediation["product_ids"])


if __name__ == "__main__":
    csaf_filename = "test_csaf.json"
    csaf = CSAFAnalyser(csaf_filename)
    print(f"{csaf_filename} a valid CSAF document : {csaf.validate()}")
    csaf.analyse()
