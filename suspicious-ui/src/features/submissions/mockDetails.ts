// src/features/submissions/mockDetails.ts
/**
 * Mock payload shaped like a "details" API response, but intentionally flexible.
 * Your normalizer/grouping code will extract analyzers + context from it.
 */
export function mockSubmissionDetails(_id: number) {
  return {
    submission_id: _id,
    type: "FILE",
    file_name: "invoice_2026_02_01.pdf",
    file_hash: "b1946ac92492d2347c6235b4d2611184",
    url: "https://example.com/payments/update",
    ip: "185.199.108.153",
    hash: "4a7d1ed414474e4033ac29ccb8653d9b",
    // The key your extractor looks for:
    analyzers: [
      {
        type: "file",
        artifact: "invoice_2026_02_01.pdf",
        analyzer_name: "FileType_Detector",
        status: "Done",
        score: 1.2,
        confidence: 93,
        level: "safe",
      },
      {
        type: "file",
        artifact: "b1946ac92492d2347c6235b4d2611184",
        analyzer_name: "YARA_Scanner",
        status: "Done",
        score: 7.8,
        confidence: 88,
        level: "malicious",
      },
      {
        type: "hash",
        artifact: "4a7d1ed414474e4033ac29ccb8653d9b",
        analyzer_name: "Hash_Reputation",
        status: "Done",
        score: 5.2,
        confidence: 72,
        level: "suspicious",
      },
      {
        type: "url",
        artifact: "https://example.com/payments/update",
        analyzer_name: "Url_Reputation",
        status: "Done",
        score: 6.4,
        confidence: 70,
        level: "malicious",
      },
      {
        type: "ip",
        artifact: "185.199.108.153",
        analyzer_name: "Ip_GeoReputation",
        status: "Done",
        score: 2.4,
        confidence: 60,
        level: "safe",
      },
      {
        type: "mail-header",
        artifact: "mail-header-hash-xxx",
        analyzer_name: "SPF_DKIM_DMARC",
        status: "Done",
        score: 3.4,
        confidence: 80,
        level: "suspicious",
      },
      {
        type: "mail-body",
        artifact: "mail-body-hash-yyy",
        analyzer_name: "Phish_Language_Model",
        status: "Done",
        score: 6.9,
        confidence: 77,
        level: "malicious",
      },
      {
        type: "attachment",
        artifact: "attachment_hash_zzz",
        analyzer_name: "Attachment_Sandbox",
        status: "Done",
        score: 8.3,
        confidence: 91,
        level: "malicious",
      },
      {
        type: "artifact",
        artifact: "login.example-secure.com",
        analyzer_name: "Domain_Reputation",
        status: "Done",
        score: 4.1,
        confidence: 65,
        level: "suspicious",
      },
    ],
    raw: {
      note: "Put anything else here; UI renders Raw details JSON too.",
    },
  };
}
