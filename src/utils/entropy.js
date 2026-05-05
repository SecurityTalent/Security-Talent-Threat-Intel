"use strict";

class EntropyUtil {
  static calculate(input) {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || "");
    if (buffer.length === 0) {
      return 0;
    }

    const frequencies = new Array(256).fill(0);
    for (const byte of buffer) {
      frequencies[byte] += 1;
    }

    let entropy = 0;
    for (const count of frequencies) {
      if (count === 0) {
        continue;
      }

      const probability = count / buffer.length;
      entropy -= probability * Math.log2(probability);
    }

    return Number(entropy.toFixed(4));
  }
}

module.exports = EntropyUtil;
