const Hasher = require('../utils/crypto');

/**
 * IOC (Indicators of Compromise) Extractor
 */
class IocExtractor {
  static extract(strings, staticResult) {
    const hashes = [];
    const files = [];
    const registry = [];
    const mutex = [];

    // Collect hashes from static analysis
    if (staticResult.hashes) {
      const h = staticResult.hashes;
      if (h.md5) hashes.push({ type: 'MD5', value: h.md5, confidence: 'HIGH' });
      if (h.sha1) hashes.push({ type: 'SHA1', value: h.sha1, confidence: 'HIGH' });
      if (h.sha256) hashes.push({ type: 'SHA256', value: h.sha256, confidence: 'HIGH' });
    }

    // Known Node.js malware IOCs (from real threat intelligence)
    const knownMalicious = {
      hashes: [
        // NodeCordRAT - bitcoin-main-lib, bitcoin-lib-js, bip40
        { type: 'MD5', value: '7a05570cda961f876e63be88eb7e12b8', family: 'NodeCordRAT', confidence: 'HIGH' },
        { type: 'MD5', value: 'c1c6f4ec5688a557fd7cc5cd1b613649', family: 'NodeCordRAT', confidence: 'HIGH' },
        { type: 'MD5', value: '9a7564542b0c53cb0333c68baf97449c', family: 'NodeCordRAT', confidence: 'HIGH' },
        // Axios/SILKBELL Supply Chain RAT
        { type: 'SHA256', value: 'e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09', family: 'SILKBELL', confidence: 'HIGH' },
        { type: 'SHA256', value: '2553649f2322049666871cea80a5d0d6adc700ca', family: 'Axios (1.14.1)', confidence: 'HIGH' },
        { type: 'SHA256', value: 'd6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71', family: 'Axios (0.30.4)', confidence: 'HIGH' },
      ],
      domains: [
        'sfrclak.com', 'callnrwise.com', 'nneewwllooggzz.mefound.com',
        'windowsupdatelogz.onedumb.com', 'jbfrost.live', 'kdark1.com'
      ],
      ips: ['142.11.206.73', '142.11.196.73', '142.11.199.73', '85.239.62.36'],
      packages: [
        'bitcoin-main-lib', 'bitcoin-lib-js', 'bip40',
        'plain-crypto-js@4.2.1', 'axios@1.14.1', 'axios@0.30.4',
        'ethers-provider2', 'ethers-providerz', 'babelcli',
        'undicy-http', 'coinbase-desktop-sdk@1.5.19',
        'react-state-optimizer-core'
      ],
      files: [
        { path: '/Library/Caches/com.apple.act.mond', platform: 'macOS' },
        { path: '/tmp/ld.py', platform: 'Linux' },
        { path: '%PROGRAMDATA%\\wt.exe', platform: 'Windows' },
        { path: '%TEMP%\\6202033.vbs', platform: 'Windows' },
        { path: '%TEMP%\\6202033.ps1', platform: 'Windows' },
        { path: '%LOCALAPPDATA%\\LogicOptimizer\\', platform: 'Windows' },
        { path: '%LOCALAPPDATA%\\LogicOptimizer\\tor\\', platform: 'Windows' }
      ],
      registry: [
        { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LogicOptimizer', family: 'ClickFix RAT' },
        { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\NodeUpdate', family: 'Generic RAT' }
      ]
    };

    // Check if strings match known IOCs
    for (const s of strings) {
      const str = s.string;
      const lower = str.toLowerCase();

      // Check file paths
      if (/^[A-Z]:\\/i.test(lower) || lower.startsWith('/') || lower.includes('\\windows\\') || 
          lower.includes('\\appdata\\') || lower.includes('\\programdata\\') || lower.includes('/tmp/')) {
        if (!files.find(f => f.path.toLowerCase() === lower)) {
          files.push({ path: str, confidence: 'MEDIUM' });
        }
      }

      // Check registry keys
      if (lower.includes('currentversion\\run') || lower.includes('currentversion\\runonce') ||
          lower.includes('hklm\\') || lower.includes('hkcu\\')) {
        if (!registry.find(r => r.key.toLowerCase() === lower)) {
          registry.push({ key: str, confidence: 'MEDIUM' });
        }
      }

      // Check mutex names
      if (lower.includes('mutex') || lower.includes('mutant') || 
          (lower.startsWith('global\\') || lower.startsWith('local\\'))) {
        mutex.push(str);
      }
    }

    // Add known IOCs that match signatures in the sample
    for (const s of strings) {
      const lower = s.string.toLowerCase();

      // Package name matching
      for (const pkg of knownMalicious.packages) {
        if (lower.includes(pkg)) {
          if (!files.find(f => f.path === pkg)) {
            files.push({ path: pkg, confidence: 'HIGH', note: `Known malicious npm package: ${pkg}` });
          }
          hashes.push({ type: 'npm_package', value: pkg, family: 'Known Malicious', confidence: 'HIGH' });
        }
      }

      // Domain matching
      for (const dom of knownMalicious.domains) {
        if (lower.includes(dom)) {
          hashes.push({ type: 'domain', value: dom, family: 'Known Malicious C2', confidence: 'HIGH' });
        }
      }

      // IP matching
      for (const ip of knownMalicious.ips) {
        if (lower.includes(ip)) {
          hashes.push({ type: 'ip', value: ip, family: 'Known Malicious C2', confidence: 'HIGH' });
        }
      }
    }

    // Detect hash-like strings in sample
    for (const s of strings) {
      const str = s.string.trim();
      // MD5
      if (/^[a-f0-9]{32}$/i.test(str) && !hashes.find(h => h.value === str)) {
        hashes.push({ type: 'MD5', value: str, confidence: 'LOW', note: 'Extracted from strings' });
      }
      // SHA1
      if (/^[a-f0-9]{40}$/i.test(str) && !hashes.find(h => h.value === str)) {
        hashes.push({ type: 'SHA1', value: str, confidence: 'LOW', note: 'Extracted from strings' });
      }
      // SHA256
      if (/^[a-f0-9]{64}$/i.test(str) && !hashes.find(h => h.value === str)) {
        hashes.push({ type: 'SHA256', value: str, confidence: 'LOW', note: 'Extracted from strings' });
      }
    }

    return { hashes, files, registry, mutex };
  }
}

module.exports = IocExtractor;