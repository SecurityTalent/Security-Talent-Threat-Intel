const config = require('../../config/default');

/**
 * Risk Assessment Engine
 * Evaluates overall threat severity, impact, and targeting profile
 */
class RiskAssessor {
  static assess(staticResult, behavioralResult, networkResult, mitreResult) {
    let score = 0;
    const findings = [];

    // ===== STATIC ANALYSIS CONTRIBUTION =====
    if (staticResult.entropy?.global > config.analysis.entropy_high) {
      score += 15;
      findings.push('HIGH_ENTROPY: Global entropy indicates encrypted/packed payload');
    }
    if (staticResult.entropy?.global > config.analysis.entropy_suspicious) {
      score += 8;
      findings.push('SUSPICIOUS_ENTROPY: Sample entropy above normal range');
    }

    if (staticResult.packed) {
      const packerName = staticResult.packed.packer || staticResult.packed;
      if (packerName !== 'None Detected' && packerName !== 'None') {
        score += 12;
        findings.push(`PACKED_DETECTED: Packer identified: ${packerName}`);
      }
    }

    if (staticResult.obfuscation && staticResult.obfuscation.length > 0) {
      score += staticResult.obfuscation.length * 6;
      findings.push(`OBFUSCATION: ${staticResult.obfuscation.length} obfuscation techniques detected`);
    }

    if (staticResult.suspicious_strings > 0) {
      score += Math.min(staticResult.suspicious_strings * 2, 20);
      findings.push(`SUSPICIOUS_STRINGS: ${staticResult.suspicious_strings} suspicious strings identified`);
    }

    if (staticResult.file_type && staticResult.file_type.toLowerCase().includes('executable')) {
      score += 5;
    }

    // ===== BEHAVIORAL ANALYSIS CONTRIBUTION =====
    if (behavioralResult.persistence && behavioralResult.persistence.length > 0) {
      score += behavioralResult.persistence.length * 8;
      findings.push(`PERSISTENCE: ${behavioralResult.persistence.length} persistence mechanisms detected`);
    }

    if (behavioralResult.actions && behavioralResult.actions.length > 0) {
      const criticalActions = behavioralResult.actions.filter(a =>
        a.toLowerCase().includes('download') || a.toLowerCase().includes('exec') ||
        a.toLowerCase().includes('inject') || a.toLowerCase().includes('steal') ||
        a.toLowerCase().includes('exfiltrat') || a.toLowerCase().includes('keylog')
      );
      score += criticalActions.length * 5;
      findings.push(`ACTIONS: ${criticalActions.length} critical actions detected`);
    }

    if (behavioralResult.privilege_escalation && behavioralResult.privilege_escalation !== 'None' && behavioralResult.privilege_escalation !== 'None Detected') {
      score += 10;
      findings.push(`PRIV_ESC: Privilege escalation technique: ${behavioralResult.privilege_escalation}`);
    }

    if (behavioralResult.injection && behavioralResult.injection !== 'None' && behavioralResult.injection !== 'None Detected') {
      score += 12;
      findings.push(`INJECTION: Process injection detected: ${behavioralResult.injection}`);
    }

    // ===== NETWORK ANALYSIS CONTRIBUTION =====
    if (networkResult.c2_detected === 'Yes') {
      score += 20;
      findings.push('C2_DETECTED: Command & Control communication infrastructure identified');
    }

    if (networkResult.domains.length > 0) {
      score += Math.min(networkResult.domains.length * 3, 15);
    }
    if (networkResult.ips.length > 0) {
      score += Math.min(networkResult.ips.length * 2, 10);
    }
    if (networkResult.urls.length > 0) {
      score += Math.min(networkResult.urls.length * 2, 10);
    }

    // ===== MITRE ATT&CK CONTRIBUTION =====
    if (mitreResult && mitreResult.length > 0) {
      score += mitreResult.length * 3;

      // Weight specific high-severity techniques
      const highSeverityTTPs = ['T1059.007', 'T1547.001', 'T1041', 'T1555.003', 'T1027', 'T1189', 'T1497.003'];
      const highTTPs = mitreResult.filter(m => highSeverityTTPs.includes(m.id));
      score += highTTPs.length * 5;
    }

    // ===== FINAL SEVERITY =====
    const severity = score >= 80 ? 'CRITICAL' :
                     score >= 60 ? 'HIGH' :
                     score >= 40 ? 'MEDIUM' :
                     score >= 20 ? 'LOW' : 'INFORMATIONAL';

    // ===== IMPACT ASSESSMENT =====
    let impact = 'Unknown';
    let target = 'General';

    // Determine impact from actions
    const allActions = (behavioralResult.actions || []).join(' ').toLowerCase();
    const allFindings = findings.join(' ').toLowerCase();

    if (allActions.includes('credential') || allActions.includes('password') ||
        allActions.includes('token') || allActions.includes('metamask') ||
        allActions.includes('wallet') || allActions.includes('seed')) {
      impact = 'Credential / Financial Theft';
      target = 'Credentials & Cryptocurrency Wallets';
    } else if (allActions.includes('ransom') || allActions.includes('encrypt') ||
               allActions.includes('decrypt')) {
      impact = 'Data Ransomware';
      target = 'File System & Data';
    } else if (allActions.includes('keylog') || allActions.includes('screenshot') ||
               allActions.includes('capture')) {
      impact = 'Surveillance & Monitoring';
      target = 'User Activity';
    } else if (allActions.includes('down') && allActions.includes('exec')) {
      impact = 'Secondary Payload Deployment';
      target = 'System Compromise';
    } else if (networkResult.c2_detected === 'Yes') {
      impact = 'Remote Access & Data Exfiltration';
      target = 'Networked Systems';
    } else if (behavioralResult.injection && !['None', 'None Detected', ''].includes(behavioralResult.injection)) {
      impact = 'Process Injection & Privilege Escalation';
      target = 'System Integrity';
    } else {
      impact = 'Suspicious Behavior';
      target = 'General';
    }

    const recommendations = this.generateRecommendations(score, findings, impact, target);

    return {
      severity,
      score,
      impact,
      target,
      findings,
      recommendations
    };
  }

  static generateRecommendations(score, findings, impact, target) {
    const recs = [];

    if (score >= 60) {
      recs.push('IMMEDIATE ACTION: Isolate affected systems from the network immediately.');
      recs.push('Conduct full incident response triage - collect forensic images of affected systems.');
    }

    if (findings.some(f => f.includes('C2_DETECTED'))) {
      recs.push('Block all identified C2 domains/IPs at firewall and DNS level. Review proxy logs for historical C2 communication.');
    }

    if (findings.some(f => f.includes('PERSISTENCE'))) {
      recs.push('Remove all identified persistence mechanisms. Scan Registry Run keys, scheduled tasks, and startup folders.');
    }

    if (impact.includes('Credential') || impact.includes('Financial')) {
      recs.push('Rotate ALL credentials, API keys, tokens, and secrets immediately. Reset MetaMask/software wallet seed phrases.');
    }

    if (findings.some(f => f.includes('OBFUSCATION'))) {
      recs.push('Perform deep deobfuscation analysis. Submit sample to automated sandbox for behavioral detonation.');
    }

    recs.push('Apply generated YARA and Sigma rules for proactive threat hunting across the environment.');
    recs.push('Review npm dependency tree for typosquatted packages, suspicious postinstall scripts, and unknown maintainers.');
    recs.push('Enable npm audit, Socket.dev scanning, or Snyk in CI/CD pipelines.');
    recs.push('Block outbound Tor traffic at network perimeter unless legitimately required.');

    return recs;
  }
}

module.exports = RiskAssessor;