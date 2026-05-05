"use strict";

const config = require("../../config/default");
const EntropyUtil = require("../utils/entropy");
const CryptoUtil = require("../utils/crypto");
const PATTERNS = require("../utils/patterns");
const StringExtractor = require("../parsers/strings");

class StaticAnalyzer {
  static analyze(input) {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || "");
    const text = buffer.toString("utf8");
    const strings = StringExtractor.extract(buffer);
    const entropy = EntropyUtil.calculate(buffer);

    const obfuscation = PATTERNS.obfuscation
      .filter((pattern) => pattern.test(text))
      .map((pattern) => pattern.toString());

    const notableStrings = strings
      .map((entry) => entry.string)
      .filter((value) =>
        /(powershell|cmd\.exe|http|tor|grpc|wallet|password|token|cookie|createremotethread|writeprocessmemory|virtualalloc)/i.test(
          value
        )
      );

    let fileType = "Unknown";
    if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
      fileType = "PE Executable";
    } else if (/module\.exports|require\(|const\s+\w+\s*=\s*require/i.test(text)) {
      fileType = "JavaScript / Node.js";
    } else if (/powershell|cmd\.exe/i.test(text)) {
      fileType = "Script / Command Payload";
    } else if (buffer.length > 0) {
      fileType = "Raw Binary";
    }

    return {
      file_type: fileType,
      entropy: {
        global: entropy
      },
      packed:
        entropy >= (config.analysis?.entropy_high || 7.5)
          ? { detected: true, packer: "High entropy / likely packed" }
          : { detected: false, packer: "None Detected" },
      suspicious_strings: notableStrings.length,
      notable_strings: notableStrings.slice(0, 50),
      obfuscation,
      hashes: CryptoUtil.all(buffer),
      strings_detail: strings
    };
  }
}

module.exports = StaticAnalyzer;
