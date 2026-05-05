"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

class JsonReporter {
  static async generate(analysisData, outputDir = "./output") {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const baseName = `threat_intel_${timestamp}`;
    const reportPath = path.join(outputDir, `${baseName}.json`);
    const summaryPath = path.join(outputDir, `${baseName}_summary.txt`);
    const stixPath = path.join(outputDir, `${baseName}_stix.json`);

    fs.writeFileSync(reportPath, JSON.stringify(analysisData, null, 2));
    fs.writeFileSync(summaryPath, this.generateSummary(analysisData));
    fs.writeFileSync(stixPath, JSON.stringify(this.generateStix(analysisData), null, 2));

    return { reportPath, summaryPath, stixPath, timestamp };
  }

  static generateSummary(data) {
    const lines = [
      "SECURITY TALENT THREAT INTEL REPORT",
      `Generated: ${new Date().toISOString()}`,
      "",
      `Type: ${data.malware_type || "Unknown"}`,
      `Family: ${data.possible_family || "Unknown / Unclassified"}`,
      `Severity: ${data.severity || "INFORMATIONAL"}`,
      `Impact: ${data.risk_assessment?.impact || "Unknown"}`,
      `Target: ${data.risk_assessment?.target || "Unknown"}`,
      "",
      "Summary:",
      data.summary || "No summary available.",
      "",
      "Domains:"
    ];

    for (const domain of data.network?.domains || []) {
      lines.push(`- ${domain}`);
    }

    lines.push("", "IPs:");
    for (const ip of data.network?.ips || []) {
      lines.push(`- ${ip}`);
    }

    lines.push("", "Recommendations:");
    for (const recommendation of data.recommendations || []) {
      lines.push(`- ${recommendation}`);
    }

    return lines.join("\n");
  }

  static generateStix(analysisData) {
    const now = new Date().toISOString();
    const bundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      spec_version: "2.1",
      objects: []
    };

    for (const hash of analysisData.iocs?.hashes || []) {
      const type = hash.type || (String(hash).length === 32 ? "MD5" : String(hash).length === 40 ? "SHA1" : "SHA256");
      const value = hash.value || hash;
      bundle.objects.push({
        type: "indicator",
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: `File Hash ${type}`,
        pattern: `[file:hashes.'${type.toLowerCase()}' = '${value}']`,
        pattern_type: "stix",
        valid_from: now
      });
    }

    for (const domain of analysisData.network?.domains || []) {
      bundle.objects.push({
        type: "indicator",
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: "Malicious Domain",
        pattern: `[domain-name:value = '${domain}']`,
        pattern_type: "stix",
        valid_from: now
      });
    }

    return bundle;
  }
}

module.exports = JsonReporter;
