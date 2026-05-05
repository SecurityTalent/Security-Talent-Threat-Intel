"use strict";

const config = require("../../config/default");

class StringExtractor {
  static extract(input) {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || "");
    const text = buffer.toString("utf8");
    const regex = /[ -~]{4,}/g;
    const seen = new Set();
    const strings = [];
    let match;

    while ((match = regex.exec(text)) !== null) {
      const value = match[0].trim();
      const minLength = config.analysis?.min_string_length || 4;
      const maxLength = config.analysis?.max_string_length || 1024;

      if (!value || value.length < minLength || value.length > maxLength || seen.has(value)) {
        continue;
      }

      seen.add(value);
      strings.push({
        string: value,
        offset: match.index,
        length: value.length,
        category: "text"
      });
    }

    return strings;
  }
}

module.exports = StringExtractor;
