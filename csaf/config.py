# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: MIT

import configparser


class CSAFConfig:
    """
    Config handler for CSAF Tool.
    """

    def __init__(self, filename):
        self.config = configparser.ConfigParser()
        self.configs = filename
        if filename != "":
            self.configs = self.config.read(filename)

    def get_sections(self):
        if self.configs != "":
            return self.config.sections()
        return []

    def get_section(self, name):
        if self.configs != "":
            return self._config_section_map(name)
        return {}

    # Helper function from https://wiki.python.org/moin/ConfigParserExamples
    def _config_section_map(self, section):
        section_dict = {}
        options = self.config.options(section)
        for option in options:
            section_dict[option] = self.config.get(section, option)
        return section_dict
