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

    lines.push("", "Runtime Modules:");
    for (const item of data.runtime_observables?.runtime_modules || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Registry Keys Opened:");
    for (const item of data.runtime_observables?.registry_keys_opened || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Files Dropped:");
    for (const item of data.runtime_observables?.files_dropped || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Files Deleted:");
    for (const item of data.runtime_observables?.files_deleted || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Files Written:");
    for (const item of data.runtime_observables?.files_written || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Files Opened:");
    for (const item of data.runtime_observables?.files_opened || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "DNS Resolutions:");
    for (const item of data.runtime_observables?.dns_resolutions || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "IP Traffic:");
    for (const item of data.runtime_observables?.ip_traffic || []) {
      lines.push(`- ${item}`);
    }

    lines.push("", "Source Attribution:");
    for (const entry of data.source_attribution || data.dark_web_intel?.enrichment || []) {
      const score = entry.detection_ratio
        ? `${entry.detection_ratio} (${entry.match_percent || 0}%)`
        : `${entry.match_percent || 0}%`;
      lines.push(`- ${entry.source}: ${entry.target} | score=${score} | confidence=${entry.confidence || "UNKNOWN"}`);
      if (entry.result_url) lines.push(`  result: ${entry.result_url}`);
      if (entry.search_url && entry.search_url !== entry.result_url) lines.push(`  search: ${entry.search_url}`);
    }

    lines.push("", "Background Hash Lookup:");
    if (data.background_hash_lookup?.enabled) {
      lines.push(`- completed: ${data.background_hash_lookup?.completed ? "yes" : "no"}`);
      for (const hash of data.background_hash_lookup?.uploaded_file_hashes || []) {
        lines.push(`- uploaded hash: ${hash}`);
      }
    } else {
      lines.push("- not triggered");
    }

    lines.push("", "External References:");
    for (const entry of data.external_references || []) {
      lines.push(`- ${entry.source}: ${entry.title || entry.url}`);
      if (entry.detail) lines.push(`  detail: ${entry.detail}`);
      if (entry.provider) lines.push(`  provider: ${entry.provider}`);
      if (entry.artifact_type) lines.push(`  artifact: ${entry.artifact_type}`);
      if (entry.access) lines.push(`  access: ${entry.access}`);
      lines.push(`  url: ${entry.url}`);
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
