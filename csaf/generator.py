# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: MIT

import json
from datetime import datetime
from pathlib import Path

from csaf.config import CSAFConfig
from csaf.version import VERSION

CSAF_ENGINE = "csaf-tool"
CSAF_CONFIG = "csaf.ini"


class CSAFGenerator:
    def __init__(self, config_filename=""):
        self.csaf_document = dict()
        self.product_list = {}
        self.vulnerabilities_list = []
        self.title = ""
        self.header_title = ""
        # Default document ID is based on time of generator
        self.id = "CSAF-Document-" + datetime.now().strftime("%Y%m%d%H%M%S")
        # Use config file is current directory if not specified
        self.config_filename = config_filename
        if self.config_filename == "":
            self.config_filename = CSAF_CONFIG
        # Check config file exists
        filePath = Path(self.config_filename)
        # Check path exists and is a valid file
        if filePath.exists() and filePath.is_file():
            # Processing can now proceed
            self.csaf_config = CSAFConfig(self.config_filename)
            self.publisher_category = self.csaf_config.get_section("publisher")[
                "category"
            ]
            self.publisher_name = self.csaf_config.get_section("publisher")["name"]
            self.publisher_url = self.csaf_config.get_section("publisher")["url"]
        else:
            # set default values
            self.publisher_category = "other"
            self.publisher_name = "ANOTHER"
            self.publisher_url = "https://www.example.com"

    def add_product(self, product_name, vendor, release):
        if product_name in self.product_list:
            # Update release
            self.product_list[product_name]["releases"].append(release)
        else:
            self.product_list[product_name] = {"vendor": vendor, "releases": [release]}

    def add_vulnerability(
        self, product_name, release, id, description, status, comment
    ):
        vulnerability = {}
        vulnerability["product"] = product_name
        vulnerability["release"] = release
        vulnerability["id"] = id
        vulnerability["description"] = description
        vulnerability["comment"] = comment
        # Check status is valid against CSAF specification
        if status in [
            "mitigation",
            "no_fix_planned",
            "none_available",
            "vendor_fix",
            "workaround",
        ]:
            vulnerability["status"] = status
        else:
            vulnerability["status"] = "none_available"
        self.vulnerabilities_list.append(vulnerability)

    def set_title(self, title):
        self.title = title

    def set_header_title(self, title):
        self.header_title = title

    def set_id(self, id):
        if id != "":
            self.id = id

    def generate_csaf(self):
        header = dict()
        header["category"] = "csaf_vex"
        header["csaf_version"] = "2.0"
        notes = []
        note_info = dict()
        note_info["category"] = "summary"
        note_info["text"] = "Auto generated CSAF document"
        note_info["title"] = self.title
        notes.append(note_info)
        header["notes"] = notes
        publisher_info = dict()
        publisher_info["category"] = self.publisher_category
        publisher_info["name"] = self.publisher_name
        publisher_info["namespace"] = self.publisher_url
        header["publisher"] = publisher_info
        header["title"] = self.header_title
        tracking_info = dict()
        tracking_info["current_release_date"] = datetime.now().strftime(
            "%Y-%m-%dT%H-%M-%SZ"
        )
        generator_info = dict()
        generator_info["date"] = datetime.now().strftime("%Y-%m-%dT%H-%M-%SZ")
        generator_engine = dict()
        generator_engine["name"] = CSAF_ENGINE
        generator_engine["version"] = VERSION
        generator_info["engine"] = generator_engine
        tracking_info["generator"] = generator_info
        tracking_info["id"] = self.id
        tracking_info["initial_relese_data"] = datetime.now().strftime(
            "%Y-%m-%dT%H-%M-%SZ"
        )
        revision = []
        revision_info = dict()
        revision_info["date"] = datetime.now().strftime("%Y-%m-%dT%H-%M-%SZ")
        revision_info["number"] = "1"
        revision_info["summary"] = "Initial version"
        revision.append(revision_info)
        tracking_info["revision_history"] = revision
        tracking_info["status"] = "final"  # Check options
        tracking_info["version"] = "1"
        header["tracking"] = tracking_info

        # Build up a product tree

        product_tree = dict()
        vendor_info = dict()
        product_info = dict()
        vendor_info["branches"] = []
        product_info["branches"] = []
        product_tree["branches"] = []

        product_id_list = dict()
        product_id = 0

        for p in self.product_list:
            # Process releases
            version_branch = []
            for v in self.product_list[p]["releases"]:
                version_info = dict()
                version_info["name"] = str(v)
                version_info["category"] = "product_version"
                product_note = dict()
                product_note["name"] = (
                    self.product_list[p]["vendor"] + " " + p + " " + str(v)
                )
                product_note["product_id"] = "PID_" + str(product_id)
                product_id += 1
                version_info["product"] = product_note
                product_id_list[p + "_" + version_info["name"]] = {
                    "name": product_note["name"],
                    "release": version_info["name"],
                    "id": product_note["product_id"],
                }
                version_branch.append(version_info)
            # Then product name
            product_info = dict()
            product_info["name"] = p
            product_info["category"] = "product_name"
            product_info["branches"] = version_branch
            # And finally vendor
            vendor_info = dict()
            vendor_info["name"] = self.product_list[p]["vendor"]
            vendor_info["category"] = "vendor"
            vendor_info["branches"] = [product_info]
            product_tree["branches"].append(vendor_info)

        # Vulnerabilities
        vulnerabilities = []

        for v in self.vulnerabilities_list:
            product = v["product"]
            version = str(v["release"])
            vuln = str(v["id"])
            desc = v["description"]
            status = v["status"]
            comment = v["comment"]
            vulnerability = dict()
            vulnerability["cve"] = vuln  # CVE ID
            note_info = dict()
            note_info["category"] = "description"
            note_info["title"] = "CVE description"
            note_info["text"] = desc
            vulnerability["note"] = note_info
            product_info = dict()
            product_info["known_affected"] = []
            product_id = product_id_list[product + "_" + version]
            product_info["known_affected"].append(product_id["id"])
            vulnerability["product_status"] = product_info
            remediation_info = dict()
            remediation_info["category"] = status
            remediation_info["details"] = comment
            product_id_info = []
            product_id_info.append(product_id)
            remediation_info["product_ids"] = product_id_info
            vulnerability["recommendation"] = remediation_info
            vulnerabilities.append(vulnerability)

        # Build up CSAF document
        self.csaf_document["document"] = header
        self.csaf_document["product_tree"] = product_tree
        self.csaf_document["vulnerabilities"] = vulnerabilities

    def publish_csaf(self, filename):
        with open(filename, "w") as outfile:
            json.dump(self.csaf_document, outfile, indent="   ")


if __name__ == "__main__":
    csaf_gen = CSAFGenerator()
    csaf_gen.set_title("Test CSAF document")
    csaf_gen.set_header_title("Example VEX Document Use Case 1 - Affected")
    csaf_gen.set_id("Avendor-advisory-0004")
    csaf_gen.add_product(product_name="product1", vendor="Avendor", release=1)
    csaf_gen.add_product(product_name="product1", vendor="Avendor", release=2)
    csaf_gen.add_product(product_name="product1", vendor="Avendor", release=3)
    csaf_gen.add_product(product_name="product2", vendor="Avendor1", release=1.0)
    csaf_gen.add_product(product_name="product2", vendor="Avendor1", release=1.1)
    csaf_gen.add_product(product_name="product3", vendor="Avendor", release=1)
    csaf_gen.add_product(product_name="product3", vendor="Avendor", release=2)
    csaf_gen.add_product(product_name="product3", vendor="Avendor", release=3)

    csaf_gen.add_vulnerability(
        product_name="product2",
        release=1.1,
        id="CVE-2020-1234",
        description="A simple example",
        status="vendor_fix",
        comment="Upgrade product to latest version.",
    )
    csaf_gen.add_vulnerability(
        product_name="product2",
        release=1.1,
        id="CVE-2020-9876",
        description="Another simple example",
        status="none_available",
        comment="Still under review.",
    )

    csaf_gen.generate_csaf()
    csaf_gen.publish_csaf("test_csaf.json")
