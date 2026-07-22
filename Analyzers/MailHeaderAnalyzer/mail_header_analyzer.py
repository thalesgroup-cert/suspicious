#!/usr/bin/env python3
# Author : THA-CERT // TBH and RBA

import email
import email.policy

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

    def _get_message(self):
        """Return a parsed email.message.Message, or None (calls self.error itself)."""
        if self.data_type == "mail_header":
            header_text = self.get_data()
            if not header_text:
                self.error("No header data provided.")
                return None
            return mail_header_analysis.parse_headers(header_text)

        if self.data_type == "file":
            filename = self.get_param("filename", "")
            if not filename.lower().endswith(".eml"):
                self.error("Only .eml files are supported for the file data type.")
                return None
            filepath = self.get_param("file", None, "File is missing")
            try:
                with open(filepath, "rb") as f:
                    return email.message_from_binary_file(f, policy=email.policy.default)
            except Exception as e:
                self.error(f"Failed to parse .eml file: {e}")
                return None

        self.error(f"Unsupported data type: {self.data_type}. Expected mail_header or file (.eml).")
        return None

    def run(self):
        Analyzer.run(self)

        msg = self._get_message()
        if msg is None:
            return

        self.report(mail_header_analysis.analyze_message(msg))


if __name__ == "__main__":
    MailHeaderAnalyzer().run()
