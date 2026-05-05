const axios = require('axios');
const { SocksProxyAgent } = require('socks-proxy-agent');
const config = require('../../config/default');

/**
 * Dark Web OSINT Intelligence Collector
 * Searches Tor hidden services and clear-web APIs for IOC correlations
 * Uses real threat intelligence from known Node.js malware campaigns
 */
class DarkWebCollector {
  /**
   * Search dark web sources for IOC mentions across multiple targets
   * @param {Array<string>} targets - IOCs to search (IPs, domains, hashes, package names)
   * @returns {Promise<object>} Dark web intelligence findings
   */
  static async search(targets) {
    const results = {
      sources_used: [],
      mentions_found: [],
      leaks: [],
      marketplaces: [],
      onion_links: [],
      correlation: [] // Links targets to known campaigns
    };

    if (!targets || targets.length === 0) return results;

    const agent = new SocksProxyAgent(config.tor.proxy);
    const searched = new Set();

    for (const target of targets.slice(0, 15)) {
      if (searched.has(target)) continue;
      searched.add(target);

      // 1. Clear-web threat intel APIs
      await this.searchAbuseIPDB(target, results, agent);
      await this.searchUrlscan(target, results);
      await this.searchVirusTotal(target, results);
      await this.searchFlare(target, results);

      // 2. Tor onion search engines (if available)
      await this.searchOnionEngines(target, results, agent);

      // 3. Known paste sites
      await this.searchPasteSites(target, results);
    }

    // 4. Cross-reference against known threat intelligence
    this.correlateKnownCampaigns(targets, results);

    // Deduplicate
    results.mentions_found = [...new Set(results.mentions_found)];
    results.onion_links = [...new Set(results.onion_links)];
    results.sources_used = [...new Set(results.sources_used)];
    results.correlation = [...new Map(
      results.correlation.map(c => [
        JSON.stringify([
          c.source || '',
          c.campaign || '',
          c.target || '',
          c.uid || '',
          c.type || ''
        ]),
        c
      ])
    ).values()];

    return results;
  }

  /**
   * Check AbuseIPDB for IP reputation
   */
  static async searchAbuseIPDB(target, results, agent) {
    if (!config.api.abuseipdb || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return;

    try {
      const resp = await axios.get(
        `${config.darkweb.clearweb.abuseipdb}/check?ipAddress=${target}&maxAgeInDays=90`,
        {
          headers: { 'Key': config.api.abuseipdb, 'Accept': 'application/json' },
          timeout: 10000
        }
      );
      if (resp.data?.data?.abuseConfidenceScore > 0) {
        const d = resp.data.data;
        results.mentions_found.push(
          `[AbuseIPDB] IP ${target}: ${d.totalReports} reports, abuse confidence ${d.abuseConfidenceScore}%`
        );
        results.sources_used.push('AbuseIPDB');
        if (d.countryCode) results.correlation.push({
          source: 'AbuseIPDB',
          target,
          country: d.countryCode,
          isp: d.isp,
          lastReported: d.lastReportedAt
        });
      }
    } catch (e) {
      // API key may be missing or quota exceeded
    }
  }

  /**
   * Check URLScan.io for domain/URL scan history
   */
  static async searchUrlscan(target, results) {
    if (!config.api.urlscan) return;

    try {
      const resp = await axios.get(
        `${config.darkweb.clearweb.urlscan}/search/?q=${encodeURIComponent(target)}`,
        { headers: { 'API-Key': config.api.urlscan }, timeout: 10000 }
      );
      if (resp.data?.results?.length > 0) {
        const count = resp.data.results.length;
        results.mentions_found.push(
          `[URLScan.io] ${count} scan results for ${target}`
        );
        results.sources_used.push('URLScan.io');

        // Check if marked malicious
        const malicious = resp.data.results.filter(r => r.page?.domain && r.result?.includes('malicious'));
        if (malicious.length > 0) {
          results.mentions_found.push(
            `[URLScan.io] ${malicious.length} scans flagged ${target} as malicious`
          );
        }
      }
    } catch (e) {
      // Silent fallback
    }
  }

  /**
   * Check VirusTotal for hash/file reputation
   */
  static async searchVirusTotal(target, results) {
    if (!config.api.virustotal || !/^[a-f0-9]{32,64}$/i.test(target)) return;

    try {
      const resp = await axios.get(
        `${config.darkweb.clearweb.virustotal}/files/${target}`,
        { headers: { 'x-apikey': config.api.virustotal }, timeout: 10000 }
      );
      if (resp.data?.data?.attributes) {
        const stats = resp.data.data.attributes.last_analysis_stats;
        const malicious = stats?.malicious || 0;
        const suspicious = stats?.suspicious || 0;
        if (malicious > 0 || suspicious > 0) {
          results.mentions_found.push(
            `[VirusTotal] ${target}: ${malicious} malicious, ${suspicious} suspicious detections`
          );
          results.sources_used.push('VirusTotal');
          results.correlation.push({
            source: 'VirusTotal',
            target,
            malicious,
            suspicious,
            undetected: stats?.undetected || 0,
            harmless: stats?.harmless || 0
          });
        }
      }
    } catch (e) {
      // Hash may not exist in VT DB
    }
  }

  /**
   * Search Flare global events API for IOC mentions
   */
  static async searchFlare(target, results) {
    if (!config.api.flare) return;

    try {
      const tokenResp = await axios.post(
        `${config.darkweb.clearweb.flare}/tokens/generate`,
        config.flare?.tenant_id ? { tenant_id: config.flare.tenant_id } : {},
        {
          headers: {
            Authorization: config.api.flare,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );

      const token = tokenResp.data?.token;
      if (!token) return;

      const searchResp = await axios.post(
        `${config.darkweb.clearweb.flare}/firework/v4/events/global/_search`,
        {
          size: Math.min(config.flare?.search_size || 5, 10),
          order: 'desc',
          query: {
            type: 'query_string',
            query_string: target
          }
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          timeout: 15000
        }
      );

      const items = searchResp.data?.items || [];
      if (items.length === 0) return;

      results.sources_used.push('Flare');
      results.mentions_found.push(`[Flare] ${items.length} event(s) found for ${target}`);

      for (const item of items.slice(0, 5)) {
        const metadata = item.metadata || {};
        const highlights = item.highlights || {};
        const snippets = Object.values(highlights)
          .flat()
          .filter(Boolean)
          .slice(0, 2)
          .map(value => String(value).replace(/\s+/g, ' ').trim());

        results.correlation.push({
          source: 'Flare',
          target,
          uid: metadata.uid,
          type: metadata.type,
          severity: metadata.severity,
          matchedAt: metadata.matched_at || metadata.estimated_created_at,
          highlights: snippets
        });

        if (snippets.length > 0) {
          results.mentions_found.push(
            `[Flare] ${metadata.type || 'event'} ${metadata.uid || ''} severity=${metadata.severity || 'unknown'} ${snippets.join(' | ').slice(0, 220)}`
          );
        }
      }
    } catch (e) {
      // Silent fallback when credentials are missing, quota is exceeded, or access is unavailable
    }
  }

  /**
   * Search Tor onion search engines for IOC mentions
   */
  static async searchOnionEngines(target, results, agent) {
    const engines = config.darkweb.engines;
    let triedCount = 0;

    for (const [name, url] of Object.entries(engines)) {
      if (triedCount >= 5) break; // Limit onion queries

      try {
        const searchUrl = `${url}/search?query=${encodeURIComponent(target)}`;
        const resp = await axios.get(searchUrl, {
          httpAgent: agent,
          httpsAgent: agent,
          timeout: config.tor.timeout
        });

        results.sources_used.push(`onion:${name}`);
        triedCount++;

        if (resp.data) {
          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);

          // Extract .onion links
          const onions = body.match(/[a-z2-7]{16,56}\.onion/gi);
          if (onions) {
            onions.forEach(o => {
              const fullUrl = `http://${o}`;
              if (!results.onion_links.includes(fullUrl)) {
                results.onion_links.push(fullUrl);
              }
            });
          }

          // Count mentions of the IOC
          const safeTarget = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const mentions = body.match(new RegExp(safeTarget, 'gi'));
          if (mentions && mentions.length > 0) {
            // Extract context (surrounding text)
            const idx = body.toLowerCase().indexOf(target.toLowerCase());
            let context = '';
            if (idx >= 0) {
              const start = Math.max(0, idx - 80);
              const end = Math.min(body.length, idx + target.length + 80);
              context = body.substring(start, end).replace(/\s+/g, ' ').trim();
            }
            results.mentions_found.push(
              `[${name}] ${mentions.length} reference(s) to ${target}: "${context.substring(0, 150)}..."`
            );
          }
        }
      } catch (e) {
        // Tor may not be running - silent
      }
    }
  }

  /**
   * Search known paste sites for IOC mentions
   */
  static async searchPasteSites(target, results) {
    const pastes = [
      { name: 'Pastebin', url: `https://psbdmp.ws/api/search/${encodeURIComponent(target)}` },
      { name: 'Ghostbin', url: `https://ghostbin.com/search?q=${encodeURIComponent(target)}` }
    ];

    for (const paste of pastes) {
      try {
        const resp = await axios.get(paste.url, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntelBot/2.0)' },
          timeout: 8000
        });
        if (resp.data && (JSON.stringify(resp.data).length > 20)) {
          results.mentions_found.push(`[${paste.name}] Data found for ${target}`);
          results.sources_used.push(paste.name);
        }
      } catch (e) {
        // Silent
      }
    }
  }

  /**
   * Cross-reference targets against known threat campaigns
   */
  static correlateKnownCampaigns(targets, results) {
    // Real threat intelligence: known Node.js malware campaigns
    const campaigns = {
      'NodeCordRAT': {
        aliases: ['nodecordrat', 'bitcoin-main-lib', 'bitcoin-lib-js', 'bip40', 'wenmoonx'],
        c2: ['discord'],
        target: 'Chrome credentials, MetaMask wallets, API tokens',
        severity: 'HIGH',
        date: 'November 2025',
        iocs: [
          '7a05570cda961f876e63be88eb7e12b8',
          'c1c6f4ec5688a557fd7cc5cd1b613649',
          '9a7564542b0c53cb0333c68baf97449c'
        ]
      },
      'SILKBELL (Axios Supply Chain)': {
        aliases: ['axios', 'silkbell', 'plain-crypto-js', 'sfrclak', 'callnrwise', 'nrwise'],
        c2: ['sfrclak.com:8000', '142.11.206.73:8000'],
        target: 'Cross-platform credential theft, crypto wallets',
        severity: 'CRITICAL',
        date: 'March 30, 2026',
        iocs: [
          'sfrclak.com', '142.11.206.73', 'callnrwise.com',
          '2553649f2322049666871cea80a5d0d6adc700ca',
          'd6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71',
          'e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09'
        ]
      },
      'ClickFix MaaS RAT': {
        aliases: ['clickfix', 'logicoptimizer', 'maas-rat'],
        c2: ['tor gRPC', 'telegram'],
        target: 'Cryptocurrency wallets via Tor-anonymized C2',
        severity: 'HIGH',
        date: 'April 2026',
        iocs: ['LogicOptimizer', 'msiexec']
      },
      'LofyGang': {
        aliases: ['lofygang', 'undicy-http', 'undici'],
        c2: ['variable - uses infected site C2'],
        target: 'Browser credentials, 90+ crypto wallets, 50+ browsers',
        severity: 'CRITICAL',
        date: 'March 2026',
        iocs: ['undicy-http']
      },
      'Vjw0rm': {
        aliases: ['vjw0rm', 'vjworm', 'java strrat'],
        c2: ['http'],
        target: 'Multi-platform credential theft, Java-based',
        severity: 'HIGH',
        date: '2024-2025'
      },
      'Ethers Supply Chain': {
        aliases: ['ethers-provider2', 'ethers-providerz', 'ethers'],
        c2: ['base64 encoded URL'],
        target: 'npm developers, crypto wallet theft',
        severity: 'HIGH',
        date: 'March 2025'
      }
    };

    for (const target of targets) {
      const lower = target.toLowerCase();

      for (const [campaign, info] of Object.entries(campaigns)) {
        // Check if any alias or IOC matches
        const aliases = info.aliases || [];
        const iocs = info.iocs || [];
        const c2 = info.c2 || [];
        const matches = aliases.some(a => lower.includes(a)) ||
          iocs.some(ioc => lower.includes(ioc.toLowerCase())) ||
          c2.some(entry => lower.includes(entry));

        if (matches) {
          results.correlation.push({
            campaign,
            description: `${campaign} campaign targeting ${info.target}`,
            severity: info.severity,
            activeSince: info.date,
            matchedOn: target,
            confidence: iocs.some(i => lower.includes(i.toLowerCase())) ? 'HIGH' : 'MEDIUM'
          });

          results.mentions_found.push(
            `[THREAT INTEL] Target "${target}" correlates with ${campaign} campaign (${info.severity}, ${info.date})`
          );
          results.sources_used.push('Threat Intelligence Correlation Engine');
        }
      }
    }
  }
}

module.exports = DarkWebCollector;
