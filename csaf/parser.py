import json
from pathlib import Path
from packageurl import PackageURL
from lib4sbom.data.vulnerability import Vulnerability

class CSAFParser:

    def __init__(self):
        self.metadata = {}

    def parse_file(self, filename):
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
        self.metadata={}
        self.product={}
        self.vulnerabilities=[]
        self._process_metadata()
        self._process_product()
        self._process_vulnerabilities()

    def _process_metadata(self):
        if len(self.data) == 0:
            return
        # Key attributes from the CSAF header

        document = self.data.get("document")
        if document is None:
            # Doesn't look like a CSAF document
            self.data = []
            return
        
        self.metadata["version"] = document["csaf_version"]
        self.metadata["title"] = document["title"]
        self.metadata["category"] = document["category"]
        self.metadata["date"] = document["tracking"]["current_release_date"]
        if "aggregate_severity" in document:
            self.metadata["severity"] = document["aggregate_severity"]["text"]
        if "notes" in document:
            notes = []
            for note in document["notes"]:
                note_ref = {'title': note["title"], 'text' : note['text'], 'category': note['category']}
                notes.append(note_ref)
            self.metadata["notes"] = notes
        if "publisher" in document:
            publisher_info = (
                f"{self.data['document']['publisher']['name']} "
                f"{self.data['document']['publisher']['namespace']}"
            )
            self.metadata["publisher"] = publisher_info
            self.metadata["author"] = self.data['document']['publisher']['name']
            self.metadata["author_url"] = self.data['document']['publisher']['namespace']
            if "contact_details" in self.data['document']['publisher']:
                self.metadata["contact_details"] = self.data['document']['publisher']['contact_details']
        if "tracking" in document:
            if "generator" in document["tracking"]:
                generator_version = "UNKNOWN"
                if (
                        "version"
                        in document["tracking"]["generator"]["engine"]
                ):
                    generator_version = document["tracking"]["generator"][
                        "engine"
                    ]["version"]
                self.metadata["generator"] = f"{self.data['document']['tracking']['generator']['engine']['name']} version {generator_version}"
            self.metadata["id"] = document["tracking"]["id"]
            self.metadata["initial_release_date"] = document["tracking"]["initial_release_date"]
            if "revision_history" in document["tracking"]:
                revision_data=[]
                for revision in document["tracking"]["revision_history"]:
                    revision_ref={'date' : revision["date"], 'number' : revision["number"], 'summary' : revision["summary"]}
                    revision_data.append(revision_ref)
                self.metadata["revision"] = revision_data
            self.metadata["tracking_status"] = document["tracking"]["status"]
            self.metadata["tracking_version"] = document["tracking"]["version"]
        if "references" in document:
            for reference in document["references"]:
                if "category" in reference:
                    self.metadata["reference_category"] = reference["category"]
                self.metadata["reference_url"] = reference["url"]
        if "distribution" in document:
            distribution_info = ""
            if "text" in document["distribution"]:
                distribution_info = f"{self.data['document']['distribution']['text']}"
            if "tlp" in document["distribution"]:
                distribution_info = (
                        distribution_info
                        + f" TLP: {self.data['document']['distribution']['tlp']['label']}"
                )
            self.metadata["distribution"] = distribution_info

    def _process_product(self):
        if len(self.data) == 0:
            return
        product = self.data["product_tree"]
        for d in product["branches"]:
            element = {}
            self._process_branch(d, element)

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
                    if id is not None and id not in self.product:
                        self.product[id] = item
                    # element = {}
        return element

    def _process_vulnerabilities(self):
        if len(self.data) == 0:
            return
        vuln_info = Vulnerability(validation="csaf")
        for vulnerability in self.data["vulnerabilities"]:
            vuln_info.initialise()
            vuln_info.set_id(vulnerability["cve"])
            if "title" in vulnerability:
                vuln_info.set_value("title", vulnerability["title"])
            if "cwe" in vulnerability:
                vuln_info.set_value("cwe",f"{vulnerability['cwe']['id']} - {vulnerability['cwe']['name']}")
            if "notes" in vulnerability:
                for note in vulnerability["notes"]:
                    vuln_info.set_value("description", note["text"])
            if "discovery_date" in vulnerability:
                vuln_info.set_value("discovery_date", vulnerability["discovery_date"])
            if "flags" in vulnerability:
                for flag in vulnerability["flags"]:
                    if "label" in flag:
                        vuln_info.set_value("justification", flag["label"])
                    vuln_info.set_value("created", flag["date"])
                    for product in flag["product_ids"]:
                        vuln_info.set_value("Product", product)
            if "ids" in vulnerability:
                for id in vulnerability["ids"]:
                    vuln_info.set_value("system_name", vulnerability["text"])
            if "references" in vulnerability:
                for reference in vulnerability["references"]:
                    vuln_info.set_value(reference["category"], [reference.get("summary",""), reference.get("url","")])
            if "release_date" in vulnerability:
                vuln_info.set_value("release_date", vulnerability["release_date"])
            if "threats" in vulnerability:
                for threat in vulnerability["threats"]:
                    vuln_info.set_value(threat["category"], threat["details"])
            if "product_status" in vulnerability:
                for product_status in vulnerability["product_status"]:
                    vuln_info.set_value("status", product_status)
            if "remediations" in vulnerability:
                for remediation in vulnerability["remediations"]:
                    vuln_info.set_remediation(remediation["category"])
                    vuln_info.set_action(remediation["details"])
            self.vulnerabilities.append(vuln_info.get_vulnerability())

    def get_metadata(self):
        return self.metadata

    def get_product(self):
        return self.product

    def get_vulnerabilities(self):
        return self.vulnerabilities

