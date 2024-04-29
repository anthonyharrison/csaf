# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: MIT

import json
from datetime import datetime, timezone
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
        self.metadata = {}
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
            self.publisher_category = "vendor"
            self.publisher_name = "ACME Inc."
            self.publisher_url = "https://www.example.com"
        self.core_product = None
        self.revision=0
        self.sbom = None

    def add_product(self, product_name, vendor, release, sbom=""):
        if len(self.product_list) == 0:
            # First product is assumed to be core product
            self.core_product = product_name + "_" + release
        if product_name in self.product_list:
            # Update release
            self.product_list[product_name]["releases"].append(release)
        elif vendor is not None:
            self.product_list[product_name] = {"vendor": vendor, "releases": [release]}
        if len(str(sbom)) > 0:
            self.sbom = Path(sbom)

    def add_vulnerability(
        self, product_name, release, id, description, status, comment, justification=None, created=None, remediation=None,action=None,
    ):
        vulnerability = {}
        vulnerability["product"] = product_name
        vulnerability["release"] = release
        vulnerability["id"] = id
        if description is not None:
            vulnerability["description"] = description
        if comment is not None:
            vulnerability["comment"] = comment
        # Check status is valid against CSAF specification
        if status in [
            "first_affected",
            "first_fixed",
            "fixed",
            "known_affected",
            "known_not_affected",
            "last_affected",
            "recommended",
            "under_investigation"
        ]:
            vulnerability["status"] = status
        else:
            # Default status
            vulnerability["status"] = "under_investigation"
        if justification is not None:
            if justification in [
                "component_not_present",
                "inline_mitigations_already_exist",
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "vulnerable_code_not_in_execute_path",
                "vulnerable_code_not_present",
            ]:
                vulnerability["justification"] = justification
        if status == "known_not_affected":
            # Justification required
            if "justification" not in vulnerability:
                # Need default justification
                vulnerability["justification"] = "component_not_present"
        if created is not None:
            vulnerability["created"] = created
        if remediation is not None:
            vulnerability["remediation"] = remediation
        if action is not None:
            vulnerability["action"] = action
        self.vulnerabilities_list.append(vulnerability)

    def set_title(self, title):
        self.title = title

    def set_header_title(self, title):
        if title != "":
            self.header_title = title

    def set_id(self, id):
        if id != "":
            self.id = id

    def set_value(self, attribute, value):
        self.metadata[attribute]=value

    def generate_csaf(self):

        time_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        header = dict()
        header["category"] = "csaf_vex"
        header["csaf_version"] = "2.0"
        notes = []
        note_info = dict()
        if "notes" in self.metadata:
            for note in self.metadata["notes"]:
                note_info["category"] = note.get('category',"other")
                note_info["title"] = note.get('title',"Author comment")
                note_info["text"] = note.get('text', "Auto generated CSAF document")
        else:
            note_info["category"] = "summary"
            note_info["title"] = self.title
            note_info["text"] = self.metadata.get("comment","Auto generated CSAF document")
            if "comment" in self.metadata:
                note_info["category"]="other"
                note_info["title"]="Author Comment"
        notes.append(note_info)
        header["notes"] = notes
        publisher_info = dict()
        publisher_info["category"] = self.publisher_category
        publisher_info["name"] = self.metadata.get("author",self.publisher_name)
        publisher_info["namespace"] = self.metadata.get("author_url",self.publisher_url)
        contact= ""
        if "supplier" in self.metadata:
            contact = self.metadata["supplier"]
            if "supplier_url" in self.metadata:
                contact = f"{contact}, {self.metadata['supplier_url']}"
        elif "contact_details" in self.metadata:
            contact = self.metadata['contact_details']
        if contact != "":
            publisher_info["contact_details"] = contact
        header["publisher"] = publisher_info
        header["title"] = self.header_title
        tracking_info = dict()
        tracking_info["current_release_date"] = time_now
        generator_info = dict()
        generator_info["date"] = time_now
        generator_engine = dict()
        generator_engine["name"] = CSAF_ENGINE
        generator_engine["version"] = VERSION
        generator_info["engine"] = generator_engine
        tracking_info["generator"] = generator_info
        tracking_info["id"] = self.id
        if self.metadata.get("initial_release_date") is None:
            tracking_info["initial_release_date"] = time_now
        else:
            tracking_info["initial_release_date"] = self.metadata.get("initial_release_date")
        revision = []
        revision_info = dict()
        if self.metadata.get("revision") is None:
            # First version of document
            revision_info["date"] = time_now
            revision_info["number"] = "1"
            revision_info["summary"] = self.metadata.get("revision_reason","Initial version")
            revision.append(revision_info)
        else:
            # Looks like this is an update to the document. Keep copy of revision history
            rev_count = 1
            for rev in self.metadata.get("revision"):
                revision.append(rev)
                rev_count += 1
            # Create new revision record for update
            revision_info["date"] = time_now
            revision_info["number"] = str(rev_count)
            revision_info["summary"] = self.metadata.get("revision_reason","Updated version")
            revision.append(revision_info)
            # Record previous revision number
            self.revision=rev_count-1
        tracking_info["revision_history"] = revision
        if "status" in self.metadata:
            tracking_info["status"] = self.metadata.get("status")
        elif "tracking_status" in self.metadata:
            tracking_info["status"] = self.metadata.get("tracking_status")
        else:
            tracking_info["status"] = self.metadata.get("status","final")  # Check options
        tracking_info["version"] = str(self.revision+1)
        header["tracking"] = tracking_info
        # Build up a product tree

        product_tree = dict()
        vendor_info = dict()
        product_info = dict()
        vendor_info["branches"] = []
        product_info["branches"] = []
        product_tree["branches"] = []

        product_id_list = dict()
        product_id = 1

        for p in self.product_list:
            # Process releases
            version_branch = []
            for v in self.product_list[p]["releases"]:
                version_info = dict()
                version_info["category"] = "product_version"
                version_info["name"] = str(v)
                product_note = dict()
                product_note["name"] = (
                    self.product_list[p]["vendor"] + " " + p + " " + str(v)
                )
                product_note["product_id"] = "CSAFPID_" + str(product_id).rjust(4,'0')
                product_id += 1
                if self.sbom is not None:
                    product_helper = dict()
                    product_helper["sbom_urls"] = [Path.as_uri(self.sbom)]
                    product_note["product_identification_helper"]=product_helper
                version_info["product"] = product_note
                product_id_list[p + "_" + version_info["name"]] = {
                    "name": product_note["name"],
                    "release": version_info["name"],
                    "id": product_note["product_id"],
                }
                version_branch.append(version_info)
            # Then product name
            product_info = dict()
            product_info["category"] = "product_name"
            product_info["name"] = p
            product_info["branches"] = version_branch
            # And finally vendor
            vendor_info = dict()
            vendor_info["category"] = "vendor"
            vendor_info["name"] = self.product_list[p]["vendor"]
            vendor_info["branches"] = [product_info]
            product_tree["branches"].append(vendor_info)

        # Vulnerabilities
        vulnerabilities = []
        product_id = product_id_list[self.core_product]

        for v in self.vulnerabilities_list:
            product = v["product"]
            version = str(v["release"])
            vuln = str(v["id"])
            desc = v.get("description", "Not known")
            status = v["status"]
            comment = v.get("comment")
            vulnerability = dict()
            vulnerability["cve"] = vuln  # CVE ID
            note_info = dict()
            note_info["category"] = "description"
            note_info["title"] = "CVE description"
            if vuln.startswith("CVE-"):
                # NVD Data source
                desc = f"https://nvd.nist.gov/vuln/detail/{vuln}"
            note_info["text"] = desc
            vulnerability["notes"] = [note_info]
            product_info = dict()
            #product_info["known_affected"] = []
            product_info[status] = []
            #product_id = product_id_list[product + "_" + version]
            product_info[status].append(product_id["id"])
            vulnerability["product_status"] = product_info
            justification = v.get("justification")
            flag_info = dict()
            # Flags only if vulnerability justification provided
            if justification is not None:
                if v.get("created") is not None:
                    # Preserve time
                    flag_info["date"] = v.get("created")
                else:
                    flag_info["date"] = time_now
                if justification is not None:
                    flag_info["label"] = justification
                flag_info["product_ids"] = [product_id["id"]]
                vulnerability["flags"] = [flag_info]
            if comment is not None:
                threat_info = dict()
                threat_info["category"] = "impact"
                threat_info["details"] = comment
                threat_info["date"] = flag_info.get("date",time_now)
                product_id_info = []
                product_id_info.append(product_id["id"])
                threat_info["product_ids"] = product_id_info
                vulnerability["threats"] = [threat_info]
            if status == "known_affected":
                remediation_info = dict()
                remediation_info["category"] = v.get("remediation","no_idea")
                remediation_info["details"] = v.get("action","Go and fix it")
                product_id_info = []
                product_id_info.append(product_id["id"])
                remediation_info["product_ids"] = product_id_info
                vulnerability["remediations"] = [remediation_info]
            vulnerabilities.append(vulnerability)

        # Build up CSAF document
        self.csaf_document["document"] = header
        self.csaf_document["product_tree"] = product_tree
        self.csaf_document["vulnerabilities"] = vulnerabilities

    def publish_csaf(self, filename):
        with open(filename, "w") as outfile:
            json.dump(self.csaf_document, outfile, indent="   ")

    def get_revision(self):
        if self.revision > 0:
            return self.revision
        return 1

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
