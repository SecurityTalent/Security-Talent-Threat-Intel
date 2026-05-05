"use strict";

const crypto = require("crypto");

class CryptoUtil {
  static hash(algorithm, input) {
    return crypto.createHash(algorithm).update(input).digest("hex");
  }

  static md5(input) {
    return this.hash("md5", input);
  }

  static sha1(input) {
    return this.hash("sha1", input);
  }

  static sha256(input) {
    return this.hash("sha256", input);
  }

  static all(input) {
    return {
      md5: this.md5(input),
      sha1: this.sha1(input),
      sha256: this.sha256(input)
    };
  }
}

module.exports = CryptoUtil;
