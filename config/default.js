require('dotenv').config();

module.exports = {
  // Tor proxy for dark web searches
  tor: {
    proxy: process.env.TOR_PROXY || 'socks5h://127.0.0.1:9050',
    timeout: parseInt(process.env.TOR_TIMEOUT || '30000'),
    retries: 3
  },

  // Dark web search engines (onion addresses)
  darkweb: {
    engines: {
      ahmia: 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion',
      onionland: 'http://3bbad7fauom4d6sgppalyqt5x6rkxz33xxlw7x6q7jvnv5y5o4rvzqd.onion',
      torgle: 'http://torgle5pr6v7k4qz.onion',
      amnesia: 'http://amnesiad2d6l2o6o.onion',
      kaizer: 'http://kaizerasi4h3q5lw.onion',
      anima: 'http://animatord7cjw5k.onion',
      tornado: 'http://tornado5h3k6q4lz.onion',
      tornet: 'http://tornet7p2q4lz5k6.onion',
      torland: 'http://torland4q7lz5k6.onion',
      findtor: 'http://findtor5p2q4lz.onion',
      excavator: 'http://excavator7j3q5l.onion',
      onionway: 'http://onionway6p4qz5k.onion',
      tor66: 'http://tor66se3z5q4l.onion',
      oss: 'http://oss7j3q5l4p2z.onion',
      torgol: 'http://torgol5h3k6q4l.onion',
      deep: 'http://deepsearch7p2q4lz.onion'
    },
    clearweb: {
      abuseipdb: 'https://api.abuseipdb.com/api/v2',
      urlscan: 'https://urlscan.io/api/v1',
      virustotal: 'https://www.virustotal.com/api/v3',
      shodan: 'https://api.shodan.io',
      malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
      flare: 'https://api.flare.io'
    }
  },

  // API keys (set via .env)
  api: {
    abuseipdb: process.env.ABUSEIPDB_KEY || '',
    virustotal: process.env.VT_KEY || '',
    shodan: process.env.SHODAN_KEY || '',
    malwarebazaar: process.env.MALWAREBAZAAR_KEY || '',
    urlscan: process.env.URLSCAN_KEY || '',
    flare: process.env.FLARE_API_KEY || ''
  },

  flare: {
    tenant_id: process.env.FLARE_TENANT_ID ? parseInt(process.env.FLARE_TENANT_ID, 10) : undefined,
    search_size: parseInt(process.env.FLARE_SEARCH_SIZE || '5', 10)
  },

  // Analysis thresholds
  analysis: {
    entropy_high: 7.5,
    entropy_suspicious: 6.0,
    max_string_length: 1024,
    min_string_length: 4,
    large_file_threshold: 10485760 // 10MB
  }
};



