"use strict";

const PATTERNS = require("../utils/patterns");

class BehavioralAnalyzer {
  static analyze(strings = []) {
    const corpus = strings.map((entry) => (typeof entry === "string" ? entry : entry.string || "")).join("\n");
    const persistence = [];
    const actions = [];

    if (/currentversion\\run|runonce/i.test(corpus)) {
      persistence.push("Registry Run Key");
    }
    if (/schtasks|scheduledtask/i.test(corpus)) {
      persistence.push("Scheduled Task");
    }
    if (/startup/i.test(corpus)) {
      persistence.push("Startup Folder");
    }
    if (/service|createservice/i.test(corpus)) {
      persistence.push("Windows Service");
    }

    if (/download|http|get|fetch|axios/i.test(corpus)) {
      actions.push("download_payload");
    }
    if (/password|cookie|token|wallet|seed|credential/i.test(corpus)) {
      actions.push("credential_theft");
    }
    if (PATTERNS.injection.some((pattern) => pattern.test(corpus))) {
      actions.push("process_injection");
    }
    if (/exec|spawn|child_process|powershell|cmd\.exe/i.test(corpus)) {
      actions.push("command_execution");
    }

    return {
      persistence: Array.from(new Set(persistence)),
      actions: Array.from(new Set(actions)),
      privilege_escalation: /runas|sedebugprivilege|uac|token/i.test(corpus)
        ? "Possible Privilege Escalation"
        : "None Detected",
      injection: actions.includes("process_injection") ? "Process Injection Detected" : "None Detected"
    };
  }
}

module.exports = BehavioralAnalyzer;
