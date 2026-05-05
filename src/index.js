#!/usr/bin/env node
const { Command } = require('commander');
const fs = require('fs');
const path = require('path');
const program = new Command();

const StaticAnalyzer = require('./analyzers/static');
const BehavioralAnalyzer = require('./analyzers/behavioral');
const NetworkAnalyzer = require('./analyzers/network');
const MitreMapper = require('./analyzers/mitre');
const RiskAssessor = require('./analyzers/risk');
const DetectionGenerator = require('./analyzers/detection');
const DarkWebCollector = require('./collectors/darkweb');
const IocExtractor = require('./collectors/ioc');
const JsonReporter = require('./reporters/json');

const STYLE = createStyle();

program
  .name('security-talent-threat-intel')
  .description('Security Talent Threat Intel')
  .version('2.0.0');

program
  .option('--file <path>', 'Analyze binary/malware file')
  .option('--hex <hex>', 'Analyze hex-encoded data')
  .option('--strings <path>', 'Analyze extracted strings file')
  .option('--logs <path>', 'Analyze network/behavioral logs')
  .option('--code <path>', 'Analyze decompiled JavaScript source')
  .option('--darkweb', 'Run dark web OSINT correlation')
  .option('--ioc <value>', 'IOC to search on dark web (IP/domain/hash)')
  .option('--report <path>', 'Output report path')
  .option('--batch <dir>', 'Batch analyze all files in directory')
  .option('--gen-yara', 'Generate YARA rules from analysis')
  .option('--gen-sigma', 'Generate Sigma rules from analysis')
  .option('--output <path>', 'Output directory for reports', './output');

program.helpInformation = function () {
  const optionLines = this.options.map((option) => {
    const flags = STYLE.flag(option.flags.padEnd(18));
    return `  ${flags} ${option.description}`;
  });

  return [
    STYLE.title('Security Talent Threat Intel'),
    STYLE.muted('Malware analysis, IOC enrichment, and dark web correlation toolkit'),
    '',
    `${STYLE.label('Usage')} ${STYLE.command('node src/index.js [options]')}`,
    '',
    STYLE.label('Options'),
    ...optionLines,
    ''
  ].join('\n');
};

async function main() {
  program.parse();
  const opts = program.opts();

  if (!fs.existsSync(opts.output)) {
    fs.mkdirSync(opts.output, { recursive: true });
  }

  let rawData = null;
  let strings = [];
  let logs = [];

  // ----- INPUT STAGE -----
  if (opts.file) {
    logInfo(`Reading file: ${opts.file}`);
    rawData = fs.readFileSync(opts.file);
    logDetail(`Size: ${rawData.length} bytes`);
  } else if (opts.hex) {
    logInfo('Decoding hex input');
    rawData = Buffer.from(opts.hex.replace(/\s+/g, ''), 'hex');
    logDetail(`Decoded: ${rawData.length} bytes`);
  } else if (opts.strings) {
    logInfo(`Reading strings file: ${opts.strings}`);
    const text = fs.readFileSync(opts.strings, 'utf-8');
    strings = text.split('\n').filter(s => s.trim()).map(s => ({
      string: s.trim(),
      offset: -1,
      entropy: 0,
      category: 'unknown'
    }));
  } else if (opts.logs) {
    logInfo(`Reading logs file: ${opts.logs}`);
    logs = JSON.parse(fs.readFileSync(opts.logs, 'utf-8'));
  } else if (opts.code) {
    logInfo(`Reading source code: ${opts.code}`);
    rawData = fs.readFileSync(opts.code);
  } else if (opts.batch) {
    logInfo(`Batch analyzing directory: ${opts.batch}`);
    const files = fs.readdirSync(opts.batch);
    const results = [];
    for (const file of files) {
      const filePath = path.join(opts.batch, file);
      if (fs.statSync(filePath).isFile()) {
        console.log(`\n${STYLE.subtleLine} ${STYLE.section(`Analyzing ${file}`)}`);
        const singleResult = await analyzeFile(filePath, opts);
        results.push({ file, result: singleResult });
      }
    }
    const batchReport = path.join(opts.output, 'batch_report.json');
    fs.writeFileSync(batchReport, JSON.stringify(results, null, 2));
    logSuccess(`Batch report saved: ${batchReport}`);
    return;
  } else if (opts.ioc) {
    logInfo(`IOC-only analysis mode: ${opts.ioc}`);
  } else {
    console.error(STYLE.error('No input provided. Use --file, --hex, --strings, --logs, --code, --batch, or --ioc'));
    process.exit(1);
  }

  // ----- MAIN ANALYSIS -----
  const result = await analyzeInput(rawData, strings, logs, opts);
  
  // Save report
  if (opts.report) {
    fs.writeFileSync(opts.report, JSON.stringify(result, null, 2));
    logSuccess(`Report saved: ${opts.report}`);
  } else {
    const defaultReport = path.join(opts.output, 'threat_intel_report.json');
    fs.writeFileSync(defaultReport, JSON.stringify(result, null, 2));
    logSuccess(`Report saved: ${defaultReport}`);
  }

  // Generate YARA if requested
  if (opts.genYara) {
    const yaraPath = path.join(opts.output, 'generated_rule.yara');
    fs.writeFileSync(yaraPath, result.detection.yara);
    logSuccess(`YARA rule saved: ${yaraPath}`);
  }

  // Generate Sigma if requested
  if (opts.genSigma) {
    const sigmaPath = path.join(opts.output, 'generated_rule_sigma.yml');
    fs.writeFileSync(sigmaPath, result.detection.sigma);
    logSuccess(`Sigma rule saved: ${sigmaPath}`);
  }

  // Print summary to console
  printSummary(result);
}

async function analyzeInput(rawData, strings, logs, opts) {
  const seededIocs = seedIocIndicators(opts.ioc);

  // Phase 1: Static Analysis
  logPhase(1, 'Static Analysis');
  let staticResult = {
    file_type: seededIocs.summaryLabel,
    packed: { detected: false, packer: 'None Detected' },
    notable_strings: opts.ioc ? [opts.ioc] : [],
    entropy: { global: 0 },
    suspicious_strings: opts.ioc ? 1 : 0,
    obfuscation: [],
    hashes: {}
  };
  
  if (rawData) {
    staticResult = StaticAnalyzer.analyze(rawData);
    MitreMapper.staticResult = staticResult;
    strings = staticResult.strings_detail || [];
    logMetric('File type', staticResult.file_type);
    logMetric('Entropy', staticResult.entropy.global);
    logMetric('Packed', staticResult.packed.packer || staticResult.packed);
    logMetric('Suspicious', `${staticResult.suspicious_strings} strings`);
    logMetric('Obfuscations', `${staticResult.obfuscation.length} techniques`);
  } else if (opts.ioc) {
    MitreMapper.staticResult = staticResult;
    logMetric('File type', staticResult.file_type);
    logMetric('Entropy', 'N/A (IOC-only mode)');
    logMetric('Packed', 'N/A (IOC-only mode)');
    logMetric('Suspicious', '1 IOC supplied');
    logMetric('Obfuscations', '0 techniques');
  }

  // Phase 2: Behavioral Analysis
  logPhase(2, 'Behavioral Analysis');
  const behavioralResult = BehavioralAnalyzer.analyze(strings, staticResult);
  logMetric('Persistence', `${behavioralResult.persistence.length} mechanisms`);
  logMetric('Actions', `${behavioralResult.actions.length} actions`);
  logMetric('Priv Esc', behavioralResult.privilege_escalation);
  logMetric('Injection', behavioralResult.injection);

  // Phase 3: Network Intelligence
  logPhase(3, 'Network Intelligence');
  const networkResult = NetworkAnalyzer.analyze(strings, logs);
  networkResult.domains = unique([...networkResult.domains, ...seededIocs.domains]);
  networkResult.ips = unique([...networkResult.ips, ...seededIocs.ips]);
  networkResult.urls = unique([...networkResult.urls, ...seededIocs.urls]);
  networkResult.c2_detected = networkResult.urls.length > 0 || networkResult.domains.length > 0 || networkResult.ips.length > 0 ? 'Yes' : 'No';
  logMetric('Domains', networkResult.domains.length);
  logMetric('IPs', networkResult.ips.length);
  logMetric('C2', networkResult.c2_detected);

  // Phase 4: IOC Extraction
  logPhase(4, 'IOC Extraction');
  const iocResult = IocExtractor.extract(strings, staticResult);
  iocResult.hashes = mergeByTypeAndValue(iocResult.hashes, seededIocs.hashes);
  iocResult.files = mergeSimpleObjects(iocResult.files, seededIocs.files, 'path');
  iocResult.registry = mergeSimpleObjects(iocResult.registry, seededIocs.registry, 'key');
  iocResult.mutex = unique([...(iocResult.mutex || []), ...(seededIocs.mutex || [])]);
  logMetric('Hashes', iocResult.hashes.length);
  logMetric('Files', iocResult.files.length);
  logMetric('Registry', iocResult.registry.length);
  logMetric('Mutex', iocResult.mutex.length);

  // Phase 5: MITRE ATT&CK Mapping
  logPhase(5, 'MITRE ATT&CK Mapping');
  const mitreResult = MitreMapper.map(strings, behavioralResult, networkResult);
  logMetric('Techniques', mitreResult.length);

  // Phase 6: Risk Assessment
  logPhase(6, 'Risk Assessment');
  const riskResult = RiskAssessor.assess(staticResult, behavioralResult, networkResult, mitreResult);
  logMetric('Severity', styleSeverity(riskResult.severity));
  logMetric('Impact', riskResult.impact);
  logMetric('Target', riskResult.target);

  // Phase 7: Detection Rules
  logPhase(7, 'Detection Rules Generation');
  const detectionResult = DetectionGenerator.generate(staticResult, networkResult, iocResult);
  logMetric('YARA', `${detectionResult.yara.length} chars`);
  logMetric('Sigma', `${detectionResult.sigma.length} chars`);

  // Phase 8: Dark Web OSINT Correlation
  let darkwebResult = {
    sources_used: [],
    mentions_found: [],
    leaks: [],
    marketplaces: [],
    onion_links: []
  };

  if (opts.darkweb || opts.ioc) {
    logPhase(8, 'Dark Web OSINT Correlation');
    const targets = unique([
      ...(opts.ioc ? [opts.ioc] : []),
      ...networkResult.domains.slice(0, 5),
      ...networkResult.ips.slice(0, 5),
      ...networkResult.urls.slice(0, 5),
      ...seededIocs.hashes.map(hash => hash.value)
    ]);

    darkwebResult = await DarkWebCollector.search(targets);
    logMetric('Sources', darkwebResult.sources_used.length);
    logMetric('Mentions', darkwebResult.mentions_found.length);
    logMetric('Onion links', darkwebResult.onion_links.length);
  }

  // Phase 9: Recommendations
  logPhase(9, 'Recommendations');
  const recommendations = generateRecommendations(staticResult, behavioralResult, networkResult, riskResult);
  const finalSummary = buildSummary(staticResult, riskResult, strings, behavioralResult, networkResult, opts, darkwebResult);
  const finalType = classifyMalwareType(strings, behavioralResult, networkResult, opts);
  const finalFamily = classifyFamily(strings, staticResult, opts, darkwebResult);

  // Build final report
  return {
    summary: finalSummary,
    malware_type: finalType,
    possible_family: finalFamily,
    severity: riskResult.severity,
    static_analysis: {
      file_type: staticResult.file_type,
      packed: staticResult.packed?.packer || staticResult.packed || 'None',
      notable_strings: (staticResult.notable_strings || []).slice(0, 50)
    },
    behavioral_analysis: {
      persistence: behavioralResult.persistence,
      actions: behavioralResult.actions,
      privilege_escalation: behavioralResult.privilege_escalation,
      injection: behavioralResult.injection
    },
    network: {
      domains: networkResult.domains.slice(0, 30),
      ips: networkResult.ips.slice(0, 30),
      urls: networkResult.urls.slice(0, 30),
      c2_detected: networkResult.c2_detected
    },
    dark_web_intel: darkwebResult,
    iocs: {
      hashes: iocResult.hashes,
      files: iocResult.files,
      registry: iocResult.registry,
      mutex: iocResult.mutex
    },
    mitre_attack: mitreResult,
    risk_assessment: {
      impact: riskResult.impact,
      target: riskResult.target
    },
    detection: {
      yara: detectionResult.yara,
      sigma: detectionResult.sigma
    },
    recommendations
  };
}

function classifyMalwareType(strings, behavioral, network, opts = {}) {
  const allStr = strings.map(s => s.string.toLowerCase()).join(' ');

  if (opts.ioc && !allStr) {
    return 'IOC Reputation / Correlation Lookup';
  }

  if (network.c2_detected === 'Yes') {
    if (allStr.includes('discord') && allStr.includes('token')) return 'RAT (Remote Access Trojan) - Discord C2';
    if (allStr.includes('grpc') || allStr.includes('tor')  || allStr.includes('.onion')) return 'RAT (Remote Access Trojan) - Tor/gRPC C2';
    if (allStr.includes('socket.io') || allStr.includes('socket')) return 'RAT (Remote Access Trojan) - Socket.io C2';
    if (allStr.includes('keylog') || allStr.includes('screenshot')) return 'Infostealer / RAT';
    if (allStr.includes('ransom') || allStr.includes('encrypt') || allStr.includes('decrypt')) return 'Ransomware';
    if (allStr.includes('wallet') || allStr.includes('seed') || allStr.includes('metamask')) return 'Cryptostealer / Infostealer';
    return 'RAT (Remote Access Trojan)';
  }
  if (allStr.includes('steal') || allStr.includes('exfiltrat') || allStr.includes('harvest')) return 'Infostealer';
  if (allStr.includes('worm') || allStr.includes('propagat') || allStr.includes('spread')) return 'Worm';
  if (behavioral.persistence.length > 0 && allStr.includes('download') && allStr.includes('exec')) return 'Dropper / Downloader';
  return 'Suspicious / Unknown';
}

function classifyFamily(strings, staticResult, opts = {}, darkwebResult = null) {
  const allStr = strings.map(s => s.string.toLowerCase()).join(' ');
  const notable = (staticResult.notable_strings || []).join(' ').toLowerCase();

  if (allStr.includes('nodecordrat') || notable.includes('nodecordrat') ||
      allStr.includes('bitcoin-main-lib') || allStr.includes('bitcoin-lib-js')) return 'NodeCordRAT';
  if (allStr.includes('plain-crypto-js') || allStr.includes('sfrclak') || 
      allStr.includes('axios') && allStr.includes('setup.js')) return 'SILKBELL (Axios Supply Chain RAT)';
  if (allStr.includes('logicoptimizer') || allStr.includes('grpc') && allStr.includes('tor')) return 'ClickFix MaaS RAT (LogicOptimizer)';
  if (allStr.includes('ethers-provider') || allStr.includes('ethers-providerz')) return 'Ethers Supply Chain RAT';
  if (allStr.includes('babelcli')) return 'Babelcli Malicious npm Package';
  if (allStr.includes('iconburst') || allStr.includes('icon') && allStr.includes('angular')) return 'IconBurst (npm Infostealer)';
  if (allStr.includes('undici') || allStr.includes('undicy')) return 'LofyGang / undici-http Malicious Package';
  if (allStr.includes('vjw0rm') || allStr.includes('vjworm')) return 'Vjw0rm';
  if (opts.ioc && darkwebResult?.correlation?.length) return darkwebResult.correlation[0].campaign;

  return 'Unknown / Unclassified';
}

function suspiciousStringsCount(staticResult) {
  return staticResult.suspicious_strings || 0;
}

function generateRecommendations(staticResult, behavioralResult, networkResult, riskResult) {
  const recs = [];

  if (networkResult.domains.length > 0 || networkResult.ips.length > 0) {
    recs.push('Block all identified C2 domains and IPs at network perimeter firewall and DNS sinkhole.');
    recs.push('Review firewall and proxy logs for any historical connections to identified C2 infrastructure.');
  }

  if (behavioralResult.persistence.length > 0) {
    recs.push('Remove persistence mechanisms: check Registry Run keys, scheduled tasks, and Startup folder.');
    recs.push('Audit all systems for unauthorized scheduled tasks and WMI event subscriptions.');
  }

  if (staticResult.obfuscation && staticResult.obfuscation.length > 0) {
    recs.push('Conduct deeper code deobfuscation using automated tools (e.g., JStill, SAFE-DEOBS).');
  }

  recs.push('Run full EDR/AV scan on all systems that may have been exposed to this sample.');
  recs.push('Review all npm dependencies for typosquatted or suspicious package names.');
  recs.push('Implement npm package verification: use `npm audit`, `socket.dev`, or `npm vet` in CI/CD pipelines.');
  recs.push('Enable runtime application self-protection (RASP) for Node.js applications.');
  recs.push('Apply the generated YARA and Sigma rules for proactive threat hunting.');
  recs.push('Rotate any credentials, API keys, tokens, or secrets that may have been exposed.');

  return recs;
}

async function analyzeFile(filePath, opts) {
  const data = fs.readFileSync(filePath);
  const result = await analyzeInput(data, [], [], {
    ...opts,
    darkweb: false,
    output: path.dirname(opts.output || './output')
  });
  return result;
}

function buildSummary(staticResult, riskResult, strings, behavioralResult, networkResult, opts, darkwebResult) {
  const subject = opts.ioc && !strings.length
    ? `IOC ${opts.ioc}`
    : staticResult.file_type || 'unknown sample';
  const correlationCount = darkwebResult?.correlation?.length || 0;
  const correlationText = correlationCount > 0
    ? ` ${correlationCount} threat intelligence correlation(s) identified.`
    : '';

  return `Threat intelligence report for ${subject}. ` +
         `Severity: ${riskResult.severity}. Type: ${classifyMalwareType(strings, behavioralResult, networkResult, opts)}. ` +
         `${suspiciousStringsCount(staticResult)} suspicious indicators identified.` +
         correlationText;
}

function seedIocIndicators(ioc) {
  const result = {
    summaryLabel: 'Unknown',
    hashes: [],
    domains: [],
    ips: [],
    urls: [],
    files: [],
    registry: [],
    mutex: []
  };

  if (!ioc) {
    return result;
  }

  const value = String(ioc).trim();
  if (!value) {
    return result;
  }

  if (/^[a-f0-9]{32}$/i.test(value)) {
    result.summaryLabel = 'IOC Hash (MD5)';
    result.hashes.push({ type: 'MD5', value, confidence: 'USER_SUPPLIED' });
  } else if (/^[a-f0-9]{40}$/i.test(value)) {
    result.summaryLabel = 'IOC Hash (SHA1)';
    result.hashes.push({ type: 'SHA1', value, confidence: 'USER_SUPPLIED' });
  } else if (/^[a-f0-9]{64}$/i.test(value)) {
    result.summaryLabel = 'IOC Hash (SHA256)';
    result.hashes.push({ type: 'SHA256', value, confidence: 'USER_SUPPLIED' });
  } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    result.summaryLabel = 'IOC IP Address';
    result.ips.push(value);
  } else if (/^https?:\/\//i.test(value)) {
    result.summaryLabel = 'IOC URL';
    result.urls.push(value);
  } else if (/[a-z0-9-]+\.[a-z]{2,}/i.test(value)) {
    result.summaryLabel = 'IOC Domain';
    result.domains.push(value);
  } else {
    result.summaryLabel = 'User Supplied IOC';
  }

  return result;
}

function unique(values) {
  return Array.from(new Set((values || []).filter(Boolean)));
}

function mergeByTypeAndValue(existing = [], seeded = []) {
  const merged = [...existing];
  const seen = new Set(existing.map(item => `${item.type || ''}|${item.value || item}`));

  for (const item of seeded) {
    const key = `${item.type || ''}|${item.value || item}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  }

  return merged;
}

function mergeSimpleObjects(existing = [], seeded = [], keyName) {
  const merged = [...existing];
  const seen = new Set(existing.map(item => item[keyName] || item));

  for (const item of seeded) {
    const key = item[keyName] || item;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  }

  return merged;
}

main().catch(err => {
  console.error(STYLE.error(`Fatal error: ${err.message}`));
  console.error(STYLE.dim(err.stack));
  process.exit(1);
});

function printSummary(result) {
  const rows = [
    ['Type', result.malware_type],
    ['Family', result.possible_family],
    ['Severity', styleSeverity(result.severity)],
    ['C2', result.network.c2_detected],
    ['Domains', result.network.domains.length],
    ['IPs', result.network.ips.length],
    ['IOCs', Object.values(result.iocs).flat().length],
    ['Dark Web', `${result.dark_web_intel.mentions_found.length} mentions`],
    ['MITRE', `${result.mitre_attack.length} techniques`]
  ];

  console.log('');
  console.log(STYLE.banner('Analysis Summary'));
  for (const [label, value] of rows) {
    console.log(`  ${STYLE.label(`${label}:`.padEnd(10))} ${value}`);
  }
  console.log(STYLE.subtleLine);
  console.log('');
}

function logPhase(number, title) {
  console.log(`\n${STYLE.section(`Phase ${number}`)} ${STYLE.text(title)}`);
}

function logMetric(label, value) {
  console.log(`  ${STYLE.label(`${label}:`.padEnd(14))} ${value}`);
}

function logInfo(message) {
  console.log(STYLE.info(`INFO  ${message}`));
}

function logSuccess(message) {
  console.log(STYLE.success(`OK    ${message}`));
}

function logDetail(message) {
  console.log(`  ${STYLE.dim(message)}`);
}

function styleSeverity(value) {
  if (value === 'CRITICAL' || value === 'HIGH') return STYLE.critical(value);
  if (value === 'MEDIUM') return STYLE.warn(value);
  if (value === 'LOW') return STYLE.info(value);
  return STYLE.dim(value);
}

function createStyle() {
  const useColor = process.stdout.isTTY && process.env.NO_COLOR !== '1';
  const wrap = (code) => (text) => useColor ? `\x1b[${code}m${text}\x1b[0m` : text;

  return {
    title: wrap('1;36'),
    banner: wrap('1;44;97'),
    section: wrap('1;34'),
    label: wrap('1;37'),
    flag: wrap('36'),
    command: wrap('32'),
    info: wrap('36'),
    success: wrap('32'),
    warn: wrap('33'),
    critical: wrap('1;31'),
    error: wrap('1;31'),
    muted: wrap('90'),
    dim: wrap('90'),
    text: wrap('37'),
    subtleLine: useColor ? '\x1b[90m──────────────────────────────────────────────\x1b[0m' : '----------------------------------------------'
  };
}
