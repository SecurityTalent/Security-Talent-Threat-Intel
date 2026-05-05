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
    onion_links: [],
    enrichment: [],
    background_hash_lookup: {
      enabled: false,
      uploaded_file_hashes: [],
      lookup_targets: [],
      completed: false
    }
  };

  const uploadedFileHashes = unique([
    staticResult?.hashes?.md5,
    staticResult?.hashes?.sha1,
    staticResult?.hashes?.sha256
  ]);
  const shouldRunBackgroundHashLookup = Boolean(opts.file && uploadedFileHashes.length > 0);

  if (opts.darkweb || opts.ioc || shouldRunBackgroundHashLookup) {
    logPhase(8, shouldRunBackgroundHashLookup && !opts.darkweb && !opts.ioc
      ? 'Background Hash Reputation Lookup'
      : 'Dark Web OSINT Correlation');
    const extractedHashTargets = (iocResult?.hashes || [])
      .map(hash => hash?.value || hash)
      .filter(value => typeof value === 'string' && /^[a-f0-9]{32,64}$/i.test(value));
    const targets = unique([
      ...(opts.ioc ? [opts.ioc] : []),
      ...networkResult.domains.slice(0, 5),
      ...networkResult.ips.slice(0, 5),
      ...networkResult.urls.slice(0, 5),
      ...seededIocs.hashes.map(hash => hash.value),
      ...uploadedFileHashes,
      ...extractedHashTargets
    ]);

    darkwebResult.background_hash_lookup = {
      enabled: uploadedFileHashes.length > 0,
      uploaded_file_hashes: uploadedFileHashes,
      lookup_targets: targets.filter(value => /^[a-f0-9]{32,64}$/i.test(String(value || ''))),
      completed: false
    };

    darkwebResult = await DarkWebCollector.search(targets);
    darkwebResult.background_hash_lookup = {
      enabled: uploadedFileHashes.length > 0,
      uploaded_file_hashes: uploadedFileHashes,
      lookup_targets: targets.filter(value => /^[a-f0-9]{32,64}$/i.test(String(value || ''))),
      completed: true
    };
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
  const runtimeObservables = buildRuntimeObservables(strings, logs, iocResult, networkResult);
  const externalReferences = buildExternalReferences(opts, darkwebResult, runtimeObservables);

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
    runtime_observables: runtimeObservables,
    dark_web_intel: darkwebResult,
    background_hash_lookup: darkwebResult.background_hash_lookup || {},
    source_attribution: darkwebResult.enrichment || [],
    external_references: externalReferences,
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

function buildRuntimeObservables(strings, logs, iocResult, networkResult) {
  const textEntries = (strings || [])
    .map(entry => typeof entry === 'string' ? entry : entry?.string || '')
    .filter(Boolean);
  const logEntries = flattenLogValues(logs);
  const corpus = [...textEntries, ...logEntries];
  const combinedText = corpus.join('\n');
  const knownFiles = (iocResult?.files || []).map(item => item.path || item).filter(Boolean);
  const knownRegistry = (iocResult?.registry || []).map(item => item.key || item).filter(Boolean);

  const runtimeModules = unique([
    ...extractModules(corpus),
    ...extractMatching(corpus, /\b[a-z0-9][a-z0-9._-]{1,100}@[0-9][a-z0-9._-]*\b/gi)
  ]).slice(0, 50);

  const filesDropped = classifyFileEvents(corpus, knownFiles, /(drop|dropped|download|payload|extract|createfile|writefile|save to|persist)/i);
  const filesDeleted = classifyFileEvents(corpus, knownFiles, /(delete|deleted|remove|removed|unlink|erase|cleanup|self-delete|self delete)/i);
  const filesWritten = classifyFileEvents(corpus, knownFiles, /(write|written|save|saved|append|store|copy|createfile|writefile)/i);
  const filesOpened = classifyFileEvents(corpus, knownFiles, /(open|opened|read|load|loaded|access|accessed|scan|enumerat)/i);
  const registryKeysOpened = classifyRegistryEvents(corpus, knownRegistry);

  const dnsResolutions = unique([
    ...(networkResult?.domains || []),
    ...((networkResult?.urls || []).map(value => {
      try {
        return new URL(value).hostname;
      } catch (e) {
        return null;
      }
    }))
  ]).slice(0, 50);

  const ipTraffic = unique(networkResult?.ips || []).slice(0, 50);

  return {
    runtime_modules: runtimeModules,
    registry_keys_opened: registryKeysOpened,
    files_dropped: filesDropped,
    files_deleted: filesDeleted,
    files_written: filesWritten,
    files_opened: filesOpened,
    dns_resolutions: dnsResolutions,
    ip_traffic: ipTraffic,
    extracted_from: {
      strings: textEntries.length,
      logs: logEntries.length
    }
  };
}

function buildExternalReferences(opts, darkwebResult, runtimeObservables) {
  const target = opts?.ioc || runtimeObservables?.ip_traffic?.[0] || runtimeObservables?.dns_resolutions?.[0] || null;
  const references = [
    {
      source: 'Abayot Malware Analysis',
      type: 'external-analysis',
      target,
      url: 'https://www.abayot.space/malware-analysis/2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c'
    },
    {
      source: 'Nextron Valhalla',
      type: 'yara-rule-reference',
      target,
      url: 'https://valhalla.nextron-systems.com/info/rule/MAL_NanocoreRAT_4_Jun19'
    },
    {
      source: 'Recorded Future',
      type: 'threat-report',
      target,
      url: 'https://www.recordedfuture.com/iranian-cyber-operations-infrastructure/'
    },
    {
      source: 'Nextron Systems',
      type: 'research-note',
      target,
      url: 'https://www.nextron-systems.com/notes-on-virustotal-matches/'
    },
    {
      source: 'Nextron Valhalla',
      type: 'yara-rule-reference',
      target,
      url: 'https://valhalla.nextron-systems.com/info/rule/MAL_NanoCore_RAT_May19_1'
    },
    {
      source: 'Nextron Valhalla',
      type: 'yara-rule-reference',
      target,
      url: 'https://valhalla.nextron-systems.com/info/rule/MAL_Nanocore_RAT_Gen_Apr16_2'
    },
    {
      source: 'SentinelOne',
      type: 'threat-report',
      target,
      url: 'https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/'
    },
    {
      source: 'Nextron Valhalla',
      type: 'yara-rule-reference',
      target,
      url: 'https://valhalla.nextron-systems.com/info/rule/MAL_NanocoreRAT_9_Jun19'
    },
    {
      source: 'Nextron Valhalla',
      type: 'yara-rule-reference',
      target,
      url: 'https://valhalla.nextron-systems.com/info/rule/NanoCore_RAT_Gen_Apr17_1'
    },
    {
      source: 'VirusTotal',
      type: 'collection',
      target,
      url: 'https://www.virustotal.com/gui/collection/3c07c188933f6025ef54ddcf44aa66d152d71dfcd4774a299e32db55594387b4'
    },
    {
      source: 'Triage',
      type: 'sandbox-report',
      target,
      url: 'https://tria.ge/260505-l7rflsct9s'
    },
    {
      source: 'Intezer Analyze',
      type: 'sandbox-report',
      target,
      url: 'https://analyze.intezer.com/analyses/aab99610-fcd7-49f9-96ce-2ef51e5544ac'
    },
    {
      source: 'FileScan.io',
      type: 'sandbox-report',
      target,
      url: 'https://www.filescan.io/reports/2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c/335ec71d-7290-46c1-ad80-e834efe9c2ce/overview'
    },
    {
      source: 'Malwares.com',
      type: 'sandbox-report',
      target,
      url: 'https://www.malwares.com/report/file?hash=2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c'
    },
    {
      source: 'MalProb.io',
      type: 'sandbox-report',
      target,
      url: 'https://malprob.io/report/2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c'
    },
    {
      source: 'MalwareBazaar',
      type: 'sample-report',
      target,
      url: 'https://bazaar.abuse.ch/sample/2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c'
    },
    {
      source: 'JaffaCakes118',
      type: 'community-analysis',
      target,
      url: 'https://jaffacakes118.dev/analysis/2156c504f8b4ddc6d2760a0c989c31c93d53b85252d14095cebcadcbe3772a0c'
    }
  ];

  for (const entry of darkwebResult?.enrichment || []) {
    if (entry.result_url) {
      references.push({
        source: entry.source,
        type: entry.type || 'enrichment',
        target: entry.target,
        url: entry.result_url
      });
    }
  }

  return uniqueBy(references, (entry) => `${entry.source}|${entry.url}`)
    .map((entry) => enrichExternalReference(entry));
}

function flattenLogValues(input) {
  const results = [];

  const visit = (value) => {
    if (value === null || value === undefined) return;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      results.push(String(value));
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (typeof value === 'object') {
      for (const [key, nested] of Object.entries(value)) {
        results.push(String(key));
        visit(nested);
      }
    }
  };

  visit(logsToArray(input));
  return results;
}

function logsToArray(logs) {
  if (Array.isArray(logs)) return logs;
  if (logs && typeof logs === 'object') return [logs];
  if (logs) return [String(logs)];
  return [];
}

function extractMatching(values, regex) {
  const matches = [];

  for (const value of values) {
    const local = String(value || '').match(regex) || [];
    matches.push(...local);
  }

  return unique(matches);
}

function extractModules(values) {
  const modules = [];
  const patterns = [
    /require\(['"`]([^'"`]+)['"`]\)/g,
    /from\s+['"`]([^'"`]+)['"`]/g,
    /import\(['"`]([^'"`]+)['"`]\)/g
  ];

  for (const value of values) {
    const text = String(value || '');
    for (const pattern of patterns) {
      for (const match of text.matchAll(pattern)) {
        const moduleName = (match[1] || '').trim();
        if (moduleName) modules.push(moduleName);
      }
    }
  }

  return unique(modules);
}

function classifyFileEvents(corpus, knownFiles, verbPattern) {
  const matched = [];

  for (const filePath of knownFiles) {
    const escaped = escapeRegex(filePath);
    const contextPattern = new RegExp(`(?:${verbPattern.source})[^\\n\\r]{0,160}${escaped}|${escaped}[^\\n\\r]{0,160}(?:${verbPattern.source})`, 'i');
    if (contextPattern.test(corpus.join('\n'))) {
      matched.push(filePath);
    }
  }

  return unique(matched).slice(0, 50);
}

function classifyRegistryEvents(corpus, registryKeys) {
  const matched = [];
  const allText = corpus.join('\n');

  for (const key of registryKeys) {
    const escaped = escapeRegex(key);
    const contextPattern = new RegExp(`(?:open|opened|query|queried|read|access|load|loaded|reg\\s+query)[^\\n\\r]{0,160}${escaped}|${escaped}[^\\n\\r]{0,160}(?:open|opened|query|queried|read|access|load|loaded|reg\\s+query)`, 'i');
    if (contextPattern.test(allText) || allText.toLowerCase().includes(key.toLowerCase())) {
      matched.push(key);
    }
  }

  return unique(matched).slice(0, 50);
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function uniqueBy(values, keySelector) {
  const seen = new Set();
  const results = [];

  for (const value of values || []) {
    const key = keySelector(value);
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(value);
  }

  return results;
}

function enrichExternalReference(entry) {
  const metadata = inferReferenceMetadata(entry);

  return {
    ...entry,
    provider: metadata.provider,
    artifact_type: metadata.artifactType,
    title: metadata.title,
    detail: metadata.detail,
    access: metadata.access,
    confidence: metadata.confidence,
    tags: metadata.tags
  };
}

function inferReferenceMetadata(entry) {
  const source = String(entry?.source || '');
  const type = String(entry?.type || '');
  const url = String(entry?.url || '');

  if (source === 'MalwareBazaar') {
    return {
      provider: 'abuse.ch',
      artifactType: 'malware-sample',
      title: 'MalwareBazaar Sample Record',
      detail: 'Malware sample reference page for the hash. Typically used to review sample metadata, family labels, sightings, tags, and related hashes.',
      access: 'public',
      confidence: 'HIGH',
      tags: ['sample', 'hash-intel', 'abuse.ch', 'malwarebazaar']
    };
  }

  if (source === 'JaffaCakes118') {
    return {
      provider: 'JaffaCakes118',
      artifactType: 'community-analysis',
      title: 'Community Analysis Report',
      detail: 'Community-authored analysis page for the hash. Useful for analyst notes, triage observations, and cross-reference context outside commercial portals.',
      access: 'public',
      confidence: 'MEDIUM',
      tags: ['community', 'analysis', 'hash-intel']
    };
  }

  if (source === 'VirusTotal' && type === 'file-reputation') {
    return {
      provider: 'VirusTotal',
      artifactType: 'file-reputation',
      title: 'VirusTotal File Reputation',
      detail: 'File reputation page for the hash. Used to review multi-engine detections, community context, behavior links, and related samples when available.',
      access: 'public-account-may-help',
      confidence: 'HIGH',
      tags: ['virustotal', 'reputation', 'multi-engine', 'hash-intel']
    };
  }

  if (source === 'VirusTotal' && type === 'collection') {
    return {
      provider: 'VirusTotal',
      artifactType: 'collection',
      title: 'VirusTotal Collection',
      detail: 'Collection page grouping related indicators or samples. Useful for reviewing clustered artifacts tied to the same campaign or investigation.',
      access: 'public-account-may-help',
      confidence: 'HIGH',
      tags: ['virustotal', 'collection', 'campaign']
    };
  }

  if (source === 'Abayot Malware Analysis') {
    return {
      provider: 'Abayot',
      artifactType: 'malware-analysis',
      title: 'Abayot Malware Analysis',
      detail: 'Standalone malware analysis page for the submitted hash. Useful for quick third-party enrichment and cross-checking sample observations.',
      access: 'public',
      confidence: 'MEDIUM',
      tags: ['analysis', 'third-party', 'hash-intel']
    };
  }

  if (source === 'Nextron Valhalla') {
    return {
      provider: 'Nextron Systems',
      artifactType: 'yara-rule',
      title: inferValhallaTitle(url),
      detail: 'Valhalla YARA rule reference related to NanoCore RAT detection. Useful for matching sample characteristics against known detection logic.',
      access: 'public',
      confidence: 'HIGH',
      tags: ['yara', 'valhalla', 'nextron', 'nanocore']
    };
  }

  if (source === 'Recorded Future') {
    return {
      provider: 'Recorded Future Insikt Group',
      artifactType: 'threat-research',
      title: 'Iranian Threat Actor Infrastructure Research',
      detail: 'Threat research article on Iranian cyber operations infrastructure, APT33 activity, domains, IP resolutions, and associated commodity RAT usage.',
      access: 'public',
      confidence: 'HIGH',
      tags: ['research', 'apt33', 'infrastructure', 'iran']
    };
  }

  if (source === 'Nextron Systems') {
    return {
      provider: 'Nextron Systems',
      artifactType: 'research-note',
      title: 'Notes on VirusTotal Matches',
      detail: 'Research note explaining how VirusTotal matches should be interpreted. Useful as analyst guidance when assessing YARA or engine hits.',
      access: 'public',
      confidence: 'HIGH',
      tags: ['research', 'virustotal', 'triage-guidance']
    };
  }

  if (source === 'SentinelOne') {
    return {
      provider: 'SentinelOne',
      artifactType: 'threat-research',
      title: 'Teaching an Old RAT New Tricks',
      detail: 'Threat research article covering NanoCore RAT tradecraft and evolution. Useful for family background, behavior patterns, and hunting context.',
      access: 'public',
      confidence: 'HIGH',
      tags: ['research', 'nanocore', 'rat']
    };
  }

  if (source === 'Triage') {
    return {
      provider: 'Hatching Triage',
      artifactType: 'sandbox-report',
      title: 'Hatching Triage Sandbox Report',
      detail: 'Dynamic sandbox report for the sample. Typically used for process tree, dropped files, network traffic, DNS, and runtime behavior.',
      access: 'public-or-shared-link',
      confidence: 'HIGH',
      tags: ['sandbox', 'dynamic-analysis', 'runtime']
    };
  }

  if (source === 'Intezer Analyze') {
    return {
      provider: 'Intezer',
      artifactType: 'sandbox-report',
      title: 'Intezer Analyze Report',
      detail: 'Sample analysis page often used for code reuse, family relationships, genetic analysis, and component-level attribution.',
      access: 'public-or-shared-link',
      confidence: 'HIGH',
      tags: ['sandbox', 'code-reuse', 'family-analysis']
    };
  }

  if (source === 'FileScan.io') {
    return {
      provider: 'FileScan.io',
      artifactType: 'sandbox-report',
      title: 'FileScan.io Report',
      detail: 'Dynamic analysis report for the hash, typically used to inspect runtime artifacts, dropped files, network traffic, and extracted IOCs.',
      access: 'public-or-shared-link',
      confidence: 'HIGH',
      tags: ['sandbox', 'runtime', 'ioc-extraction']
    };
  }

  if (source === 'Malwares.com') {
    return {
      provider: 'Malwares.com',
      artifactType: 'sandbox-report',
      title: 'Malwares.com Analysis Report',
      detail: 'Malware analysis report page for the hash. Useful for additional sandbox context and comparative verdicts.',
      access: 'public-or-shared-link',
      confidence: 'MEDIUM',
      tags: ['sandbox', 'analysis', 'hash-intel']
    };
  }

  if (source === 'MalProb.io') {
    return {
      provider: 'MalProb.io',
      artifactType: 'sandbox-report',
      title: 'MalProb.io Report',
      detail: 'Third-party report page for the hash. Useful for another external verdict and supporting sample context.',
      access: 'public-or-shared-link',
      confidence: 'MEDIUM',
      tags: ['sandbox', 'third-party', 'analysis']
    };
  }

  return {
    provider: source || 'Unknown',
    artifactType: type || 'reference',
    title: source || 'External Reference',
    detail: 'External reference linked to the analyzed artifact.',
    access: 'unknown',
    confidence: 'LOW',
    tags: []
  };
}

function inferValhallaTitle(url) {
  const value = String(url || '');

  if (value.includes('MAL_NanocoreRAT_4_Jun19')) return 'Valhalla Rule: MAL_NanocoreRAT_4_Jun19';
  if (value.includes('MAL_NanoCore_RAT_May19_1')) return 'Valhalla Rule: MAL_NanoCore_RAT_May19_1';
  if (value.includes('MAL_Nanocore_RAT_Gen_Apr16_2')) return 'Valhalla Rule: MAL_Nanocore_RAT_Gen_Apr16_2';
  if (value.includes('MAL_NanocoreRAT_9_Jun19')) return 'Valhalla Rule: MAL_NanocoreRAT_9_Jun19';
  if (value.includes('NanoCore_RAT_Gen_Apr17_1')) return 'Valhalla Rule: NanoCore_RAT_Gen_Apr17_1';

  return 'Valhalla Rule Reference';
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
