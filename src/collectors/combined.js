"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const StringExtractor = require("../parsers/strings");
const StaticAnalyzer = require("../analyzers/static");
const BehavioralAnalyzer = require("../analyzers/behavioral");
const NetworkAnalyzer = require("../analyzers/network");
const MitreMapper = require("../analyzers/mitre");
const RiskAssessor = require("../analyzers/risk");
const DetectionGenerator = require("../analyzers/detection");
const IocCollector = require("./ioc");
const DarkWebCollector = require("./darkweb");
const JsonReporter = require("../reporters/json");

class CombinedPipeline {
  static async run(filePath, options = {}) {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`File not found: ${absolutePath}`);
    }

    const rawBuffer = fs.readFileSync(absolutePath);
    const strings = StringExtractor.extract(rawBuffer);
    const staticResult = StaticAnalyzer.analyze(rawBuffer);
    MitreMapper.staticResult = staticResult;
    const behavioralResult = BehavioralAnalyzer.analyze(strings, staticResult);
    const networkResult = NetworkAnalyzer.analyze(strings, []);
    const iocs = IocCollector.extract(strings, staticResult);
    const mitreTechniques = MitreMapper.map(strings, behavioralResult, networkResult);
    const riskAssessment = RiskAssessor.assess(staticResult, behavioralResult, networkResult, mitreTechniques);
    const detections = DetectionGenerator.generate(staticResult, networkResult, iocs);
    const darkWebIntel = await DarkWebCollector.search([
      ...networkResult.domains,
      ...networkResult.ips,
      ...networkResult.urls
    ]);

    const analysisData = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      file: {
        name: path.basename(absolutePath),
        path: absolutePath,
        size: rawBuffer.length,
        extension: path.extname(absolutePath).toLowerCase(),
        md5: crypto.createHash("md5").update(rawBuffer).digest("hex"),
        sha1: crypto.createHash("sha1").update(rawBuffer).digest("hex"),
        sha256: crypto.createHash("sha256").update(rawBuffer).digest("hex")
      },
      summary: riskAssessment.findings.join("; "),
      malware_type: staticResult.file_type || "Unknown",
      possible_family: "Unknown / Unclassified",
      severity: riskAssessment.severity || "INFORMATIONAL",
      static_analysis: staticResult,
      behavioral_analysis: behavioralResult,
      network: networkResult,
      iocs,
      mitre_attack: mitreTechniques,
      risk_assessment: {
        score: riskAssessment.score,
        severity: riskAssessment.severity,
        impact: riskAssessment.impact,
        target: riskAssessment.target,
        summary: riskAssessment.findings.join("; "),
        recommendations: riskAssessment.recommendations
      },
      detection: detections,
      recommendations: riskAssessment.recommendations,
      dark_web_intel: darkWebIntel,
      pipeline_version: "2.0.0"
    };

    const outDir = options.outputDir || "./output";
    const reportMeta = await JsonReporter.generate(analysisData, outDir);
    return { ...analysisData, ...reportMeta };
  }

  static async batch(filePaths, options = {}) {
    const results = [];
    for (const filePath of filePaths) {
      try {
        results.push(await CombinedPipeline.run(filePath, options));
      } catch (error) {
        results.push({ file: filePath, error: error.message });
      }
    }

    return results;
  }
}

module.exports = CombinedPipeline;
