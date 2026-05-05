/**
 * Detection Rule Generator
 * Creates YARA and Sigma rules from analysis findings
 */
class DetectionGenerator {
  static generate(staticResult, networkResult, iocResult) {
    const yara = this.generateYara(staticResult, networkResult, iocResult);
    const sigma = this.generateSigma(staticResult, networkResult, iocResult);
    return { yara, sigma };
  }

  /**
   * Generate YARA rule for this specific sample
   */
  static generateYara(staticResult, networkResult, iocResult) {
    const strings = staticResult.notable_strings || [];
    const domains = networkResult.domains || [];
    const ips = networkResult.ips || [];
    const hashes = iocResult.hashes || [];
    const files = iocResult.files || [];
    const registry = iocResult.registry || [];

    const ruleName = 'SUSP_NodeJS_Malware_' + (staticResult.entropy?.global ? 
      Math.round(staticResult.entropy.global * 10) : 'Unknown');

    let yara = `rule ${ruleName} : malware_nodejs_rat\n{\n    meta:\n        description = "Automatically generated YARA rule for Node.js malware detection"\n        author = "Security Talent Threat Intel v2.0"\n        date = "${new Date().toISOString().split('T')[0]}"\n        reference = "Security Talent Threat Intel"\n`;

    // Add known family references
    if (staticResult.possible_family && staticResult.possible_family !== 'Unknown / Unclassified') {
      yara += `        malware_family = "${staticResult.possible_family}"\n`;
    }

    if (domains.length > 0) {
      yara += `        c2_domains = "${domains.slice(0, 5).join(', ')}"\n`;
    }
    if (ips.length > 0) {
      yara += `        c2_ips = "${ips.slice(0, 5).join(', ')}"\n`;
    }

    yara += `        hash_md5 = "${hashes.find(h => h.type === 'MD5')?.value || ''}"\n`;
    yara += `        hash_sha256 = "${hashes.find(h => h.type === 'SHA256')?.value || ''}"\n    \n    strings:\n`;

    // String patterns from the sample (hex-safe)
    let stringIdx = 1;
    const usedStrings = [];

    for (const s of strings.slice(0, 20)) {
      const str = typeof s === 'string' ? s : (s.string || s);
      if (str.length < 6 || str.length > 200) continue;
      if (str.includes('\x00')) continue;
      if (usedStrings.includes(str)) continue;
      usedStrings.push(str);

      // Escape for YARA
      const escaped = str
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');

      if (str.length > 8 && /^[\x20-\x7E\s]+$/.test(str)) {
        yara += `        $s${stringIdx} = "${escaped}" wide ascii\n`;
        stringIdx++;
      }
    }

    // Add domain strings
    for (const dom of domains.slice(0, 10)) {
      if (!usedStrings.includes(dom)) {
        yara += `        $s${stringIdx} = "${dom}" wide ascii\n`;
        usedStrings.push(dom);
        stringIdx++;
      }
    }

    // Add IP strings
    for (const ip of ips.slice(0, 5)) {
      if (!usedStrings.includes(ip)) {
        yara += `        $s${stringIdx} = "${ip}" wide ascii\n`;
        usedStrings.push(ip);
        stringIdx++;
      }
    }

    // Add registry key strings
    for (const reg of registry.slice(0, 5)) {
      const key = reg.key || reg;
      if (!usedStrings.includes(key)) {
        yara += `        $s${stringIdx} = "${key}" wide ascii\n`;
        usedStrings.push(key);
        stringIdx++;
      }
    }

    // Add file path strings
    for (const file of files.slice(0, 5)) {
      const path = file.path || file;
      if (!usedStrings.includes(path) && typeof path === 'string') {
        yara += `        $s${stringIdx} = "${path}" wide ascii\n`;
        usedStrings.push(path);
        stringIdx++;
      }
    }

    // Hex patterns for obfuscated strings
    const obfuscatedStrings = strings.filter(s => {
      const str = typeof s === 'string' ? s : (s.string || '');
      return str.length > 10 && /[\\x%][0-9a-f]{2}/i.test(str);
    });

    for (const obs of obfuscatedStrings.slice(0, 10)) {
      const str = typeof obs === 'string' ? obs : (obs.string || '');
      if (!usedStrings.includes(str)) {
        // Convert to hex for YARA
        let hex = '';
        for (let i = 0; i < str.length && i < 64; i++) {
          hex += str.charCodeAt(i).toString(16).padStart(2, '0');
        }
        yara += `        $hex${stringIdx} = { ${hex} }\n`;
        usedStrings.push(str);
        stringIdx++;
      }
    }

    // Build condition
    if (stringIdx > 1) {
      const totalStrings = stringIdx - 1;
      const minMatch = Math.min(3, totalStrings);
      yara += `    \n    condition:\n        ${totalStrings <= 5 ? 'any of them' : `${minMatch} of them`}\n}\n`;
    } else {
      yara += `    \n    condition:\n        false // No distinct strings found\n}\n`;
    }

    return yara;
  }

  /**
   * Generate Sigma rule for this specific sample
   */
  static generateSigma(staticResult, networkResult, iocResult) {
    const domains = networkResult.domains || [];
    const ips = networkResult.ips || [];
    const files = iocResult.files || [];
    const hashes = iocResult.hashes || [];

    const ruleId = `sigma-${Date.now().toString(36)}`;

    let sigma = `title: Node.js Malware Detection - ${staticResult.file_type || 'Unknown Sample'}\n`;
    sigma += `id: ${ruleId}\n`;
    sigma += `status: experimental\n`;
    sigma += `description: |\n`;
    sigma += `    Detects indicators of Node.js malware based on analysis of sample.\n`;
    sigma += `    Generated by Security Talent Threat Intel v2.0.\n`;
    sigma += `    Correlated with known campaigns (NodeCordRAT, SILKBELL, ClickFix, LofyGang).\n`;
    sigma += `author: Security Talent Threat Intel (Automated)\n`;
    sigma += `date: ${new Date().toISOString().split('T')[0]}\n`;
    sigma += `references:\n`;
    sigma += `    - Security Talent Threat Intel\n`;
    sigma += `    - https://www.zscaler.com/es/blogs/security-research/malicious-npm-packages-deliver-nodecordrat\n`;
    sigma += `    - https://socket.dev/blog/axios-npm-package-compromised\n`;
    sigma += `    - https://socprime.com/active-threats/clickfix-to-maas-inside-a-modular-windows-rat-and-its-control-panel/\n`;
    sigma += `    - https://research.jfrog.com/post/lofygang-returns-a-dual-payload-npm-package/\n`;

    // Log source - process creation (primary for Node.js execution)
    sigma += `logsource:\n`;
    sigma += `    category: process_creation\n`;
    sigma += `    product: windows\n`;
    sigma += `detection:\n`;

    // Node.js execution detection with suspicious command lines
    sigma += `    selection_node:\n`;
    sigma += `        Image|endswith: '\\node.exe'\n`;
    sigma += `        CommandLine|contains:\n`;
    sigma += `            - 'execSync'\n`;
    sigma += `            - 'child_process'\n`;
    sigma += `            - 'http'\n`;
    sigma += `            - '.onion'\n`;
    sigma += `            - 'grpc'\n`;
    sigma += `            - 'socks5'\n`;
    sigma += `            - 'DownloadString'\n`;
    sigma += `            - 'WebClient'\n`;

    // Network connection detection
    if (domains.length > 0 || ips.length > 0) {
      sigma += `    selection_network:\n`;
      sigma += `        - Image|endswith: '\\node.exe'\n`;
      if (domains.length > 0) {
        sigma += `        - DestinationHostname|contains:\n`;
        for (const dom of domains.slice(0, 10)) {
          sigma += `            - '${dom}'\n`;
        }
      }
      if (ips.length > 0) {
        sigma += `        - DestinationIp|contains:\n`;
        for (const ip of ips.slice(0, 10)) {
          sigma += `            - '${ip}'\n`;
        }
      }
    }

    // File creation of known indicators
    if (files.length > 0) {
      sigma += `    selection_file:\n`;
      sigma += `        TargetFilename|endswith:\n`;
      for (const file of files.slice(0, 10)) {
        const path = file.path || file;
        if (typeof path === 'string' && path.length > 3) {
          sigma += `            - '${path.replace(/%[^%]+%/g, '')}'\n`;
        }
      }
    }

    // Registry persistence detection
    sigma += `    selection_registry:\n`;
    sigma += `        TargetObject|contains:\n`;
    sigma += `            - 'CurrentVersion\\\\Run\\\\Node'\n`;
    sigma += `            - 'CurrentVersion\\\\Run\\\\LogicOptimizer'\n`;

    // Hash-based detection
    if (hashes.length > 0) {
      sigma += `    selection_hash:\n`;
      sigma += `        Hashes:\n`;
      for (const hash of hashes.slice(0, 5)) {
        const val = hash.value || hash;
        if (typeof val === 'string' && val.length >= 32) {
          sigma += `            - '${val}'\n`;
        }
      }
    }

    // Mageck process creation via scripts
    sigma += `    selection_script:\n`;
    sigma += `        - Image|endswith: '\\cscript.exe'\n`;
    sigma += `          CommandLine|contains: '.vbs'\n`;
    sigma += `        - Image|endswith: '\\wscript.exe'\n`;
    sigma += `          CommandLine|contains: '.js'\n`;
    sigma += `        - Image|endswith: '\\powershell.exe'\n`;
    sigma += `          CommandLine|contains:\n`;
    sigma += `            - 'node'\n`;
    sigma += `            - 'npm'\n`;
    sigma += `            - 'axios'\n`;

    // Condition
    sigma += `    condition: 1 of selection_*\n`;
    sigma += `falsepositives:\n`;
    sigma += `    - Legitimate Node.js development activity\n`;
    sigma += `    - Authorized npm package installations\n`;
    sigma += `level: high\n`;

    return sigma;
  }
}

module.exports = DetectionGenerator;
