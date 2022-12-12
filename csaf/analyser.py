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

    def validate(self):
        # Does this document look like a CSAF document?
        if (
            "document" in self.data
            and "product_tree" in self.data
            and "vulnerabilities" in self.data
        ):
            return True
        return False

    def _show_product(self, item):
        vendor = item["vendor"]
        product = item["product_name"]
        version = item["product_version"]
        print(f"{vendor} {product} {version}")

    def _print(self, attribute, information):
        print(f"{attribute:40} : {information}")

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

    def analyse(self):
        # Aabort analysis if not a valid CSAF document
        if not self.validate():
            print(f"[ERROR] {self.filename} is not a valid CSAF document")
            return

        # Key attributes from the CSAF header
        print("Header")
        print("======\n")
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
            generator_version = "UNKNOWN"
            if "version" in self.data["document"]["tracking"]["generator"]["engine"]:
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
                    self._multiline(f"Revision {revision['number']} {revision['date']}", revision['summary'])
            self._print("Status", self.data["document"]["tracking"]["status"])
            self._print("Version", self.data["document"]["tracking"]["version"])
        if "distribution" in self.data["document"]:
            distribution_info = (
                f"{self.data['document']['distribution']['text']}")
            if "tlp" in self.data['document']['distribution']:
                distribution_info = distribution_info + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
            self._print("Distribution", distribution_info)
        # Show product tree
        print("\nProduct Tree")
        print("============\n")
        product_list = {}
        for d in self.data["product_tree"]["branches"]:
            vendor = d["name"]
            for b in d["branches"]:
                for p in b:
                    product = b["name"]
                    if "branches" in b:
                        for q in b["branches"]:
                            version = q["name"]
                            item = {}
                            item["vendor"] = vendor
                            item["product"] = product
                            item["version"] = version
                            if "branches" in q:
                                # Service pack
                                for s in q["branches"]:
                                    id = s["product"]["product_id"]
                                    if id not in product_list:
                                        product_list[id] = item
                            else:
                                id = q["product"]["product_id"]
                                if id not in product_list:
                                    product_list[id] = item

        print("Product                        Vendor                         Release")
        print("-" * 90)
        for entry in product_list:
            product = product_list[entry]
            print(
                f"{product['product']:30} {product['vendor']:30} {product['version']}"
            )

        print("\nVulnerabilities")
        print("===============")
        for d in self.data["vulnerabilities"]:
            if "note" in d:
                print(f"\n{d['cve']} {d['note']['text']}")
            else:
                print(f"\n{d['cve']}")
            if "product_status" in d and "known_affected" in d["product_status"]:
                for p in d["product_status"]["known_affected"]:
                    if p in product_list:
                        x = product_list[p]
                        print(
                            f"Product: {x['product']:30} "
                            f"Vendor: {x['vendor']:30} "
                            f"Version: {x['version']}"
                        )
                    else:
                        # Just show product ID
                        print(f"Product: {p:30} ")
            if "recommendation" in d:
                fix = d["recommendation"]["category"]
                details = d["recommendation"]["details"]
                self._multiline(fix, details)
                if "product_ids" in d:
                    for p in d["recommendation"]["product_ids"]:
                        if p in product_list:
                            x = product_list[p]
                            print(
                                f"Product: {x['product']:30} "
                                f"Vendor: {x['vendor']:30} "
                                f"Version: {x['version']}"
                            )
                        else:
                            print(f"Product Id: {p}")
            if "remediations" in d:
                for remediation in d["remediations"]:
                    fix = remediation["category"]
                    details = remediation["details"]
                    self._multiline(fix, details)
                    if "product_ids" in remediation:
                        for p in remediation["product_ids"]:
                            if p in product_list:
                                x = product_list[p]
                                print(
                                    f"Product: {x['product']:30} "
                                    f"Vendor: {x['vendor']:30} "
                                    f"Version: {x['version']}"
                                )
                            else:
                                print(f"Product Id: {p}")


if __name__ == "__main__":
    csaf_filename = "test_csaf.json"
    csaf = CSAFAnalyser(csaf_filename)
    print(f"Is {csaf_filename} a valid CSAF document : {csaf.validate()}")
    csaf.analyse()
