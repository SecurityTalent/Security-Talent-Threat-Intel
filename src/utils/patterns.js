"use strict";

module.exports = {
  urls: /\bhttps?:\/\/[^\s"'<>]+/gi,
  domains: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
  ips: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  registry: /\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"'<>]+/gi,
  files: /\b[A-Z]:\\[^\r\n\t"'<>|?*]+/gi,
  mutex: /\b(?:mutex|mutant|global\\|local\\)[a-z0-9._\\-]*/gi,
  obfuscation: [
    /powershell\s+-enc/i,
    /frombase64string/i,
    /eval\s*\(/i,
    /atob\s*\(/i,
    /charcodeat/i,
    /fromcharcode/i,
    /xor/i
  ],
  persistence: [
    /currentversion\\run/i,
    /currentversion\\runonce/i,
    /schtasks/i,
    /startup/i,
    /createservice/i,
    /service/i
  ],
  injection: [
    /createremotethread/i,
    /writeprocessmemory/i,
    /virtualalloc/i,
    /queueuserapc/i,
    /process hollow/i
  ]
};
