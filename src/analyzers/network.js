"use strict";

const PATTERNS = require("../utils/patterns");

function uniq(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

class NetworkAnalyzer {
  static analyze(strings = [], logs = []) {
    const corpus = [
      ...strings.map((entry) => (typeof entry === "string" ? entry : entry.string || "")),
      ...(Array.isArray(logs) ? logs : [String(logs || "")])
    ].join("\n");

    const urls = uniq(corpus.match(PATTERNS.urls) || []);
    const ips = uniq(corpus.match(PATTERNS.ips) || []);
    const domains = uniq([
      ...urls.map((value) => {
        try {
          return new URL(value).hostname;
        } catch {
          return "";
        }
      }),
      ...((corpus.match(PATTERNS.domains) || []).filter((value) => !ips.includes(value)))
    ]);

    return {
      domains,
      ips,
      urls,
      c2_detected: urls.length > 0 || domains.length > 0 || ips.length > 0 ? "Yes" : "No"
    };
  }
}

module.exports = NetworkAnalyzer;
