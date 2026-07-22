#!/usr/bin/env python3
# Author : THA-CERT // TBH and RBA

from cortexutils.analyzer import Analyzer

import mail_header_analysis


class MailHeaderAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = [
            self.build_taxonomy(t["level"], "MailHeaderAnalyzer", t["predicate"], t["value"])
            for t in raw.get("taxonomies", [])
        ]
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type != "mail_header":
            self.error(f"Unsupported data type: {self.data_type}. Expected mail_header.")
            return

        header_text = self.get_data()
        if not header_text:
            self.error("No header data provided.")
            return

        self.report(mail_header_analysis.analyze(header_text))


if __name__ == "__main__":
    MailHeaderAnalyzer().run()
