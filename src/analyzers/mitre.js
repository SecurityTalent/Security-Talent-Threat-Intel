/**
 * MITRE ATT&CK Framework Mapper
 * Maps observed behaviors to MITRE ATT&CK techniques and tactics
 * Includes real-world Node.js malware TTPs from known campaigns
 * 
 * Supported tactics: Execution, Persistence, Privilege Escalation,
 *   Defense Evasion, Credential Access, Discovery, Collection,
 *   Command and Control, Exfiltration, Impact, Initial Access
 */
class MitreMapper {
  /**
   * Map all observed behaviors to MITRE ATT&CK techniques
   * @param {Array} strings - Extracted strings from sample
   * @param {object} behavioralResult - Behavioral analysis results
   * @param {object} networkResult - Network intelligence results
   * @returns {Array} List of matched MITRE ATT&CK technique objects
   */
  static map(strings, behavioralResult, networkResult) {
    const techniques = [];
    const allStr = strings.map(s => {
      if (typeof s === 'string') return s.toLowerCase();
      if (s.string) return s.string.toLowerCase();
      return '';
    }).join(' ');

    const allActions = (behavioralResult.actions || []).join(' ').toLowerCase();
    const allPersistence = (behavioralResult.persistence || []).join(' ').toLowerCase();

    // ===========================================================
    // INITIAL ACCESS
    // ===========================================================

    // T1189: Drive-by Compromise
    if (allStr.includes('clickfix') || allStr.includes('click fix') ||
        allStr.includes('msi') || (allStr.includes('update') && allStr.includes('fix')) ||
        allStr.includes('browser') && allStr.includes('error') ||
        allStr.includes('copy') && allStr.includes('paste') ||
        allStr.includes('clipboard')) {
      techniques.push({
        id: 'T1189',
        tactic: 'Initial Access',
        technique: 'Drive-by Compromise',
        description: 'ClickFix lures trick users into executing malicious PowerShell/Node.js commands via browser clipboard manipulation',
        reference: 'Netskope April 2026: ClickFix campaign using MSI installers delivering Node.js RAT via Tor gRPC C2',
        severity: 'HIGH'
      });
    }

    // T1566.001: Spearphishing Attachment
    if (allStr.includes('.zip') || allStr.includes('attachment') || allStr.includes('email') ||
        allStr.includes('invoice') || allStr.includes('document.pdf') || allStr.includes('docm') ||
        allStr.includes('invoice') || allStr.includes('receipt')) {
      techniques.push({
        id: 'T1566.001',
        tactic: 'Initial Access',
        technique: 'Spearphishing Attachment',
        description: 'Malicious attachment delivered via email containing Node.js dropper or installer',
        severity: 'HIGH'
      });
    }

    // T1195.001: Supply Chain Compromise
    if (allStr.includes('npm install') || allStr.includes('npm publish') || allStr.includes('package.json') ||
        allStr.includes('postinstall') || allStr.includes('typosquat') || allStr.includes('dependency') ||
        allStr.includes('bitcoin-main-lib') || allStr.includes('bitcoin-lib-js') || allStr.includes('bip40') ||
        allStr.includes('plain-crypto-js') || allStr.includes('ethers-provider') || allStr.includes('undicy-http') ||
        allStr.includes('axios@1.14.1') || allStr.includes('axios@0.30.4')) {
      techniques.push({
        id: 'T1195.001',
        tactic: 'Initial Access',
        technique: 'Supply Chain Compromise: Malicious Dependencies',
        description: 'Malicious npm packages delivered via supply chain: typosquatting, dependency confusion, or account takeover',
        reference: 'NodeCordRAT (bitcoin-main-lib, bitcoin-lib-js, bip40), SILKBELL (plain-crypto-js@4.2.1 in axios), LofyGang (undicy-http)',
        severity: 'CRITICAL'
      });
    }

    // ===========================================================
    // EXECUTION
    // ===========================================================

    // T1059.007: Command and Scripting Interpreter: JavaScript/Node.js
    if (allStr.includes('require(') || allStr.includes('process.') || 
        allStr.includes('module.exports') || allStr.includes('node.exe') ||
        allStr.includes('.js') || allStr.includes('node ') ||
        allStr.includes('npx ') || allStr.includes('npm ') ||
        allStr.includes('node.exe') || allStr.includes('nodejs') ||
        (allStr.includes('const ') && allStr.includes('= require'))) {
      techniques.push({
        id: 'T1059.007',
        tactic: 'Execution',
        technique: 'Command and Scripting Interpreter: JavaScript/Node.js',
        description: 'JavaScript executed via Node.js runtime for malware delivery, persistence, and C2 communication',
        reference: 'Microsoft April 2025 report: Threat actors misuse Node.js to deliver malware and establish persistence via registry Run keys, scheduled tasks',
        severity: 'HIGH'
      });
    }

    // T1204.002: User Execution: Malicious File
    if (allStr.includes('.vbs') || allStr.includes('.ps1') || allStr.includes('.msi') ||
        allStr.includes('.bat') || allStr.includes('.cmd') || allStr.includes('cscript') || 
        allStr.includes('wscript') || allStr.includes('powershell') || allStr.includes('cmd.exe') ||
        allStr.includes('msiexec') || allStr.includes('6202033.vbs') || allStr.includes('6202033.ps1')) {
      techniques.push({
        id: 'T1204.002',
        tactic: 'Execution',
        technique: 'User Execution: Malicious File',
        description: 'User tricked into executing VBScript, PowerShell, or MSI dropper that loads Node.js RAT payload',
        reference: 'Axios/SILKBELL: 6202033.vbs -> 6202033.ps1 execution chain. ClickFix: MSI installer with Node.js runtime',
        severity: 'MEDIUM'
      });
    }

    // T1053.005: Scheduled Task
    if (allPersistence.includes('schtasks') || allPersistence.includes('task') ||
        allPersistence.includes('cron') || allStr.includes('schtasks') || 
        allStr.includes('CreateService') || allStr.includes('Win32_ScheduledJob') ||
        allStr.includes('ScheduledTask')) {
      techniques.push({
        id: 'T1053.005',
        tactic: 'Execution',
        technique: 'Scheduled Task',
        description: 'Creates scheduled task for execution or persistence of Node.js payload',
        severity: 'HIGH'
      });
    }

    // T1106: Native API
    if (allStr.includes('CreateProcess') || allStr.includes('CreateRemoteThread') ||
        allStr.includes('VirtualAlloc') || allStr.includes('NtCreate') ||
        allStr.includes('WriteProcessMemory') || allStr.includes('kernel32') ||
        allStr.includes('ntdll')) {
      techniques.push({
        id: 'T1106',
        tactic: 'Execution',
        technique: 'Native API',
        description: 'Windows Native API calls for process creation, memory manipulation, and code injection',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // PERSISTENCE
    // ===========================================================

    // T1547.001: Registry Run Keys / Startup Folder
    if (allPersistence.includes('run') || allPersistence.includes('runonce') ||
        allPersistence.includes('currentversion\\run') || allStr.includes('currentversion\\run') ||
        allStr.includes('logicoptimizer') || allStr.includes('hkcu\\run') ||
        allStr.includes('hklm\\software\\microsoft\\windows\\currentversion\\run') ||
        allStr.includes('startup') || allStr.includes('\\startmenu\\programs\\startup')) {
      techniques.push({
        id: 'T1547.001',
        tactic: 'Persistence',
        technique: 'Boot or Logon Autostart Execution: Registry Run Keys',
        description: 'Persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run or Startup folder',
        reference: 'ClickFix RAT (LogicOptimizer), Shai-Hulud worm, Microsoft-documented Node.js campaigns (April 2025)',
        severity: 'HIGH'
      });
    }

    // T1053.005: Scheduled Task/Job (Persistence variant)
    // (Already added above under Execution, add Persistence variant)
    if (allPersistence.includes('task') || allPersistence.includes('schtasks') ||
        allPersistence.includes('cron') || allStr.includes('schtasks') || 
        allStr.includes('at ') || allStr.includes('CreateService')) {
      // Only add if not already a Persistence variant
      const persistenceTask = techniques.find(t => t.id === 'T1053.005' && t.tactic === 'Persistence');
      if (!persistenceTask) {
        techniques.push({
          id: 'T1053.005',
          tactic: 'Persistence',
          technique: 'Scheduled Task/Job',
          description: 'Persistence via scheduled task creation that re-executes Node.js payload at system boot or user logon',
          severity: 'HIGH'
        });
      }
    }

    // T1543.003: Windows Service
    if (allStr.includes('CreateService') || allStr.includes('OpenSCManager') ||
        allStr.includes('StartService') || allStr.includes('sc.exe') ||
        allStr.includes('sc create') || allPersistence.includes('service')) {
      techniques.push({
        id: 'T1543.003',
        tactic: 'Persistence',
        technique: 'Windows Service',
        description: 'Installs as Windows service for persistence',
        severity: 'MEDIUM'
      });
    }

    // T1574.002: DLL Side-Loading
    if (allStr.includes('.dll') && (allStr.includes('load') || allStr.includes('sideload') ||
        allStr.includes('rundll32') || allStr.includes('DllMain') || allStr.includes('DllRegisterServer') ||
        allStr.includes('DllGetClassObject'))) {
      techniques.push({
        id: 'T1574.002',
        tactic: 'Persistence',
        technique: 'DLL Side-Loading',
        description: 'Malicious DLL sideloaded by legitimate Node.js or Windows processes via search order hijacking',
        reference: 'Ontinue: DLL sideload + JS-based C2 backdoor executed via Node.js with socket.io, node-cmd, hardcoded credentials',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // DEFENSE EVASION
    // ===========================================================

    // T1027: Obfuscated Files or Information
    const hasHighEntropy = MitreMapper.staticResult?.entropy?.global > 6.0;
    if (hasHighEntropy || MitreMapper.staticResult?.obfuscation?.length > 0 ||
        allStr.includes('base64') || allStr.includes('atob(') || allStr.includes('btoa(') ||
        allStr.includes('eval(') || allStr.includes('escape(') || allStr.includes('unescape(') ||
        allStr.includes('charCodeAt') || allStr.includes('\\x') || /\\x[0-9a-f]{2}/i.test(allStr) ||
        (MitreMapper.staticResult?.entropy?.global > 6.0)) {
      techniques.push({
        id: 'T1027',
        tactic: 'Defense Evasion',
        technique: 'Obfuscated Files or Information',
        description: 'JavaScript obfuscation (base64 encoding, eval-based XOR encoding, high entropy strings, character code manipulation)',
        reference: 'Common in all Node.js malware: NodeCordRAT (eval+base64), SILKBELL (base64-encoded PowerShell), Vjw0rm',
        severity: 'MEDIUM'
      });
    }

    // T1027.010: Command Obfuscation
    if (allStr.includes('Split(') || allStr.includes('Join(') || allStr.includes('Reverse(') ||
        allStr.includes('replace(') || allStr.includes('substring(') || allStr.includes('substr(') ||
        allStr.includes('concat(') || allStr.includes('fromCharCode(') ||
        (allStr.match(/['"][a-z]{2,10}\([^)]+\)/gi)?.length > 5)) {
      techniques.push({
        id: 'T1027.010',
        tactic: 'Defense Evasion',
        technique: 'Command Obfuscation',
        description: 'JS function chaining for string obfuscation (split/reverse/join, fromCharCode, replace patterns)',
        severity: 'MEDIUM'
      });
    }

    // T1564.001: Hidden Files and Directories
    if (allStr.includes('appdata\\local\\') || allStr.includes('\\temp\\') ||
        allStr.includes('/tmp/') || allStr.includes('hidden') ||
        allStr.includes('attrib +h') || allStr.includes('.cache') ||
        allStr.includes('\\logicoptimizer\\') || allStr.includes('com.apple.act.mond') ||
        allStr.includes('ld.py')) {
      techniques.push({
        id: 'T1564.001',
        tactic: 'Defense Evasion',
        technique: 'Hidden Files and Directories',
        description: 'Malware stores payloads in hidden/temp/cache directories to evade casual inspection',
        reference: 'ClickFix: LogicOptimizer folder. SILKBELL: /Library/Caches/com.apple.act.mond (macOS), /tmp/ld.py (Linux)',
        severity: 'MEDIUM'
      });
    }

    // T1497.003: Time Based Evasion
    if (allStr.includes('sleep') || allStr.includes('setTimeout') || allStr.includes('setInterval') ||
        allStr.includes('Date.now') || allStr.includes('getTime') || allStr.includes('performance') ||
        allStr.includes('setTimeout') || allStr.includes('wait(')) {
      techniques.push({
        id: 'T1497.003',
        tactic: 'Defense Evasion',
        technique: 'Time Based Evasion',
        description: 'Delay execution via setTimeout/setInterval to evade sandbox and dynamic analysis timeouts',
        reference: 'Common evasion technique in Node.js RATs — delays before C2 beaconing or payload activation',
        severity: 'MEDIUM'
      });
    }

    // T1497.001: System Checks (VM/Sandbox Detection)
    if (allStr.includes('detect') || allStr.includes('sandbox') || allStr.includes('virtualbox') ||
        allStr.includes('vmware') || allStr.includes('vbox') || allStr.includes('qemu') ||
        allStr.includes('hyper') || allStr.includes('check') && (allStr.includes('vm') || allStr.includes('virt'))) {
      techniques.push({
        id: 'T1497.001',
        tactic: 'Defense Evasion',
        technique: 'System Checks: VM/Sandbox Detection',
        description: 'Checks for virtualized environment before executing malicious payload',
        reference: 'ClickFix RAT: checked host against 30+ security solutions before dynamic module loading',
        severity: 'HIGH'
      });
    }

    // T1070.004: File Deletion / Self-Cleanup
    if (allStr.includes('delete') || allStr.includes('unlink') || allStr.includes('rm ') ||
        allStr.includes('fs.unlink') || allStr.includes('removeFile') || allStr.includes('selfdestruct') ||
        allStr.includes('self destruct') || allStr.includes('cleanup') || allStr.includes('kill')) {
      techniques.push({
        id: 'T1070.004',
        tactic: 'Defense Evasion',
        technique: 'Indicator Removal: File Deletion',
        description: 'Self-deletes installer/payload files after execution to cover tracks (forensic artifact removal)',
        reference: 'SILKBELL: Deletes setup.js, install.js and replaces package.json after installation',
        severity: 'MEDIUM'
      });
    }

    // ===========================================================
    // CREDENTIAL ACCESS
    // ===========================================================

    // T1555.003: Credentials from Web Browsers
    if (allStr.includes('chrome') || allStr.includes('browser') || allStr.includes('password') ||
        allStr.includes('cookie') || allStr.includes('session') || allStr.includes('login') ||
        allStr.includes('credentials') || allStr.includes('localstorage') || allStr.includes('local state') ||
        allStr.includes('web data') || allStr.includes('login data') || allStr.includes('cookies') ||
        allStr.includes('autofill')) {
      techniques.push({
        id: 'T1555.003',
        tactic: 'Credential Access',
        technique: 'Credentials from Web Browsers',
        description: 'Extracts saved credentials, cookies, and autofill data from Chrome and Chromium-based browsers',
        reference: 'NodeCordRAT: Chrome credential theft. LofyGang: 50+ browser credential harvesting via PE injection',
        severity: 'CRITICAL'
      });
    }

    // T1555.006: Cloud Secrets / Cryptocurrency Wallet Theft
    if (allStr.includes('metamask') || allStr.includes('wallet') || allStr.includes('seed') ||
        allStr.includes('private key') || allStr.includes('mnemonic') || allStr.includes('bip39') ||
        allStr.includes('bip32') || allStr.includes('ethereum') || allStr.includes('bitcoin') ||
        allStr.includes('coinbase') || allStr.includes('phantom') || allStr.includes('keplr') ||
        allStr.includes('trust wallet') || allStr.includes('exodus')) {
      techniques.push({
        id: 'T1555.006',
        tactic: 'Credential Access',
        technique: 'Cloud Secrets / Cryptocurrency Wallet Theft',
        description: 'Steals MetaMask seed phrases, private keys, and crypto wallet extension data from browser storage',
        reference: 'NodeCordRAT (bitcoin-main-lib, bip40 packages): MetaMask private keys and seed phrases. ClickFix MaaS RAT: real-time Telegram wallet theft alerts. LofyGang: 90+ crypto wallet extensions',
        severity: 'CRITICAL'
      });
    }

    // T1555.004: Windows Credential Manager
    if (allStr.includes('credential manager') || allStr.includes('vault') || allStr.includes('credman') ||
        allStr.includes('CredEnumerate') || allStr.includes('CredRead') || allStr.includes('vaultcli')) {
      techniques.push({
        id: 'T1555.004',
        tactic: 'Credential Access',
        technique: 'Windows Credential Manager',
        description: 'Dumps credentials from Windows Credential Manager and Windows Vault',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // COLLECTION
    // ===========================================================

    // T1056.001: Input Capture: Keylogging
    if (allStr.includes('keylog') || allStr.includes('keypress') || allStr.includes('keydown') ||
        allStr.includes('keyup') || allStr.includes('keyboard') || allStr.includes('iohook') ||
        allStr.includes('onkey') || allStr.includes('addEventListener') && allStr.includes('key')) {
      techniques.push({
        id: 'T1056.001',
        tactic: 'Collection',
        technique: 'Input Capture: Keylogging',
        description: 'Logs keystrokes to capture credentials, sensitive data, and crypto wallet passwords',
        severity: 'HIGH'
      });
    }

    // T1113: Screen Capture
    if (allStr.includes('screenshot') || allStr.includes('capture') || allStr.includes('screen') ||
        allStr.includes('display') || allStr.includes('puppeteer') || allStr.includes('canvas') ||
        allStr.includes('screencapture') || allStr.includes('CaptureScreen')) {
      techniques.push({
        id: 'T1113',
        tactic: 'Collection',
        technique: 'Screen Capture',
        description: 'Captures screenshots of infected systems for data exfiltration or surveillance',
        severity: 'MEDIUM'
      });
    }

    // T1115: Clipboard Data
    if (allStr.includes('clipboard') || allStr.includes('readtext') || allStr.includes('getclipboard') ||
        allStr.includes('copy') && allStr.includes('paste') || allStr.includes('execCommand(\'copy\'')) {
      techniques.push({
        id: 'T1115',
        tactic: 'Collection',
        technique: 'Clipboard Data',
        description: 'Reads clipboard contents to capture copied passwords, wallet addresses, or crypto seed phrases',
        reference: 'ClickFix: Browser clipboard manipulation for payload delivery',
        severity: 'MEDIUM'
      });
    }

    // T1119: Automated Collection
    if (allStr.includes('collect') && (allStr.includes('all') || allStr.includes('auto') ||
        allStr.includes('gather') || allStr.includes('harvest'))) {
      techniques.push({
        id: 'T1119',
        tactic: 'Collection',
        technique: 'Automated Collection',
        description: 'Automated harvesting of files, credentials, and system data',
        severity: 'MEDIUM'
      });
    }

    // ===========================================================
    // COMMAND AND CONTROL
    // ===========================================================

    // T1071.001: Web Protocols (HTTP/HTTPS)
    if (allStr.includes('http://') || allStr.includes('https://') || 
        allStr.includes('.post(') || allStr.includes('.get(') || allStr.includes('axios') ||
        allStr.includes('request(') || allStr.includes('fetch(') || allStr.includes('xmlhttp') ||
        allStr.includes('ajax') || allStr.includes('superagent')) {
      techniques.push({
        id: 'T1071.001',
        tactic: 'Command and Control',
        technique: 'Application Layer Protocol: Web Protocols',
        description: 'HTTP/HTTPS used for C2 communication, data exfiltration, and payload download',
        severity: 'MEDIUM'
      });
    }

    // T1573.001: Encrypted Channel: Symmetric Cryptography
    if (allStr.includes('aes') || allStr.includes('rc4') || allStr.includes('xor') ||
        allStr.includes('encrypt') || allStr.includes('decrypt') || allStr.includes('cipher') ||
        allStr.includes('crypto') || allStr.includes('createCipher') || allStr.includes('createDecipher')) {
      techniques.push({
        id: 'T1573.001',
        tactic: 'Command and Control',
        technique: 'Encrypted Channel: Symmetric Cryptography',
        description: 'C2 communication encrypted with symmetric cryptography (AES, RC4, XOR-based rolling keys)',
        severity: 'HIGH'
      });
    }

    // T1090.003: Multi-hop Proxy (Tor)
    if (allStr.includes('tor') || allStr.includes('.onion') || allStr.includes('socks5') ||
        allStr.includes('socks') || allStr.includes('proxy') || allStr.includes('tor expert') ||
        allStr.includes('torproject')) {
      techniques.push({
        id: 'T1090.003',
        tactic: 'Command and Control',
        technique: 'Multi-hop Proxy: Tor',
        description: 'C2 traffic routed through Tor anonymous network via SOCKS5 proxy or Tor Expert Bundle',
        reference: 'ClickFix MaaS RAT: Tor Expert Bundle download, SOCKS5 proxy setup, gRPC streaming over Tor. C2 tracking nearly impossible',
        severity: 'CRITICAL'
      });
    }

    // T1572: Protocol Tunneling
    if (allStr.includes('grpc') || allStr.includes('protobuf') || allStr.includes('protocol buffer') ||
        allStr.includes('streaming') || allStr.includes('tunnel')) {
      techniques.push({
        id: 'T1572',
        tactic: 'Command and Control',
        technique: 'Protocol Tunneling',
        description: 'gRPC streaming protocol used for persistent bidirectional C2 communication (often over Tor)',
        reference: 'ClickFix MaaS RAT: gRPC streaming over Tor for real-time C2',
        severity: 'CRITICAL'
      });
    }

    // T1095: Non-Application Layer Protocol
    if (allStr.includes('socket') || allStr.includes('tcp') || allStr.includes('websocket') ||
        allStr.includes('socket.io') || allStr.includes('socketio')) {
      techniques.push({
        id: 'T1095',
        tactic: 'Command and Control',
        technique: 'Non-Application Layer Protocol',
        description: 'Raw socket/TCP or WebSocket communication for C2, including Socket.IO real-time bidirectional channels',
        reference: 'Ontinue: socket.io + node-cmd backdoor with hardcoded credentials',
        severity: 'HIGH'
      });
    }

    // T1105: Ingress Tool Transfer
    if (allStr.includes('download') || allStr.includes('curl') || allStr.includes('wget') ||
        allStr.includes('http.get') || allStr.includes('axios.get') || allStr.includes('fetch(') ||
        allStr.includes('request(') || allStr.includes('DownloadFile') || allStr.includes('DownloadString')) {
      techniques.push({
        id: 'T1105',
        tactic: 'Command and Control',
        technique: 'Ingress Tool Transfer',
        description: 'Downloads additional payloads, modules, or stage 2 implants from C2 server',
        reference: 'SILKBELL: axios dependency downloads platform-specific payload via /product0 (macOS), /product1 (Windows), /product2 (Linux) endpoints. NodeCordRAT: Discord C2 delivering stage 2 modules',
        severity: 'HIGH'
      });
    }

    // T1219: Remote Access Software
    if (allStr.includes('rat') || allStr.includes('trojan') || allStr.includes('backdoor') ||
        allStr.includes('remote access') || allStr.includes('shell') || allStr.includes('execSync') ||
        allStr.includes('spawnSync') || allStr.includes('exec(') || allStr.includes('execSync(') ||
        allStr.includes('spawn(') || allStr.includes('child_process') ||
        (behavioralResult?.injection && behavioralResult.injection !== 'None' && 
         behavioralResult.injection !== 'None Detected' && behavioralResult.injection !== '')) {
      techniques.push({
        id: 'T1219',
        tactic: 'Command and Control',
        technique: 'Remote Access Software',
        description: 'Full RAT capability: remote shell execution, file system access, reverse shell, command execution via child_process',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // EXFILTRATION
    // ===========================================================

    // T1041: Exfiltration Over C2 Channel
    if (networkResult?.c2_detected === 'Yes') {
      techniques.push({
        id: 'T1041',
        tactic: 'Exfiltration',
        technique: 'Exfiltration Over C2 Channel',
        description: 'Data exfiltrated via same HTTP/HTTPS/Socket channel used for C2 communication',
        reference: 'SILKBELL: Exfiltrates via HTTP POST to sfrclak.com:8000. API tokens, credentials, wallet data sent in POST body',
        severity: 'CRITICAL'
      });
    }

    // T1567: Exfiltration Over Web Service
    if (allStr.includes('discord') || allStr.includes('pastebin') || allStr.includes('slack') ||
        allStr.includes('github') || allStr.includes('telegram') || allStr.includes('webhook')) {
      techniques.push({
        id: 'T1567',
        tactic: 'Exfiltration',
        technique: 'Exfiltration Over Web Service',
        description: 'Exfiltrates stolen data via web services (Discord webhook, Telegram bot, Pastebin API, GitHub Gist)',
        reference: 'NodeCordRAT: Discord server as C2/exfiltration channel. ClickFix: Telegram alert notifications for successful wallet thefts',
        severity: 'CRITICAL'
      });
    }

    // T1020: Automated Exfiltration
    if (allStr.includes('auto') && (allStr.includes('exfil') || allStr.includes('send'))) {
      techniques.push({
        id: 'T1020',
        tactic: 'Exfiltration',
        technique: 'Automated Exfiltration',
        description: 'Automatically exfiltrates collected data at intervals or on trigger events',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // IMPACT
    // ===========================================================

    // T1485: Data Destruction
    if (allStr.includes('delete') || allStr.includes('wipe') || allStr.includes('self destruct') ||
        allStr.includes('selfdestruct') || allStr.includes('unlink') || allStr.includes('rm -rf') ||
        allStr.includes('empty') || allStr.includes('clear')) {
      // Only add if not added as T1070.004 earlier
      const existingT1070 = techniques.find(t => t.id === 'T1070.004');
      if (!existingT1070) {
        techniques.push({
          id: 'T1485',
          tactic: 'Impact',
          technique: 'Data Destruction',
          description: 'Destroys or corrupts data to cause damage or cover tracks after exfiltration',
          reference: 'SILKBELL: Self-deletes installer artifacts after execution. Replaces package.json with clean version',
          severity: 'HIGH'
        });
      }
    }

    // T1486: Data Encrypted for Impact
    if (allStr.includes('encrypt') && (allStr.includes('ransom') || allStr.includes('.encrypted') ||
        allStr.includes('.locked') || allStr.includes('.crypted'))) {
      techniques.push({
        id: 'T1486',
        tactic: 'Impact',
        technique: 'Data Encrypted for Impact',
        description: 'Encrypts victim files for ransom or data destruction',
        severity: 'CRITICAL'
      });
    }

    // ===========================================================
    // DISCOVERY
    // ===========================================================

    // T1082: System Information Discovery
    if (allStr.includes('os.platform') || allStr.includes('os.hostname') || allStr.includes('os.arch') ||
        allStr.includes('os.release') || allStr.includes('process.platform') || allStr.includes('process.arch') ||
        allStr.includes('process.version') || allStr.includes('systeminfo') || allStr.includes('uname') ||
        allStr.includes('hostname') || allStr.includes('os') && allStr.includes('cpus')) {
      techniques.push({
        id: 'T1082',
        tactic: 'Discovery',
        technique: 'System Information Discovery',
        description: 'Enumerates OS type, version, architecture, hostname for victim fingerprinting',
        reference: 'NodeCordRAT: platform detection, host fingerprinting. SILKBELL: platform check (product0/1/2)',
        severity: 'LOW'
      });
    }

    // T1083: File and Directory Discovery
    if (allStr.includes('readdir') || allStr.includes('readdirSync') || allStr.includes('ls ') ||
        allStr.includes('dir ') || allStr.includes('find ') || allStr.includes('glob(') ||
        allStr.includes('walk')) {
      techniques.push({
        id: 'T1083',
        tactic: 'Discovery',
        technique: 'File and Directory Discovery',
        description: 'Enumerates files and directories to locate targets (credentials, wallets, sensitive docs)',
        severity: 'MEDIUM'
      });
    }

    // T1012: Query Registry
    if (allStr.includes('reg query') || allStr.includes('registry') || allStr.includes('regedit') ||
        allStr.includes('Win32_Reg') || allStr.includes('RegistryKey')) {
      techniques.push({
        id: 'T1012',
        tactic: 'Discovery',
        technique: 'Query Registry',
        description: 'Enumerates Windows Registry for installed software, browser data locations, and security settings',
        severity: 'LOW'
      });
    }

    // T1057: Process Discovery
    if (allStr.includes('process') && (allStr.includes('list') || allStr.includes('ps ') || 
        allStr.includes('tasklist') || allStr.includes('wmic process') || allStr.includes('Get-Process'))) {
      techniques.push({
        id: 'T1057',
        tactic: 'Discovery',
        technique: 'Process Discovery',
        description: 'Enumerates running processes to identify security tools, browsers, or wallet software',
        reference: 'ClickFix RAT: checks for 30+ security solutions before executing payload',
        severity: 'MEDIUM'
      });
    }

    // ===========================================================
    // RESOURCE DEVELOPMENT
    // ===========================================================

    // T1583.001: Acquire Infrastructure: Domains
    if (allStr.includes('register') || allStr.includes('domain') || allStr.includes('sfrclak') ||
        allStr.includes('callnrwise') || allStr.includes('kdark1')) {
      techniques.push({
        id: 'T1583.001',
        tactic: 'Resource Development',
        technique: 'Acquire Infrastructure: Domains',
        description: 'Malicious domains used for C2 infrastructure',
        reference: 'sfrclak[.]com, callnrwise[.]com, kdark1[.]com (SILKBELL and Veracode RAT campaigns)',
        severity: 'MEDIUM'
      });
    }

    // T1587.001: Develop Capabilities: Malware
    if (allStr.includes('build') || allStr.includes('compile') || allStr.includes('pack') ||
        allStr.includes('generate') || allStr.includes('create')) {
      techniques.push({
        id: 'T1587.001',
        tactic: 'Resource Development',
        technique: 'Develop Capabilities: Malware',
        description: 'Builds or compiles malicious payloads dynamically',
        severity: 'MEDIUM'
      });
    }

    // ===========================================================
    // LATERAL MOVEMENT
    // ===========================================================

    // T1091: Replication Through Removable Media
    if (allStr.includes('usb') || allStr.includes('removable') || allStr.includes('drive') ||
        allStr.includes('autorun') || allStr.includes('worm') || allStr.includes('spread') ||
        allStr.includes('propagat')) {
      techniques.push({
        id: 'T1091',
        tactic: 'Lateral Movement',
        technique: 'Replication Through Removable Media',
        description: 'Spreads via USB/drive for lateral movement (worm behavior)',
        reference: 'Vjw0rm: USB-based propagation alongside Java STRRAT delivery',
        severity: 'HIGH'
      });
    }

    // ===========================================================
    // FINAL: Deduplicate and Sort
    // ===========================================================

    // Remove duplicates by ID + tactic
    const seen = new Set();
    const deduped = techniques.filter(t => {
      const key = `${t.id}|${t.tactic}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Sort by severity
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    deduped.sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

    return deduped;
  }
}

// Reference to staticResult needed for entropy - stored on the class
MitreMapper.staticResult = null;

module.exports = MitreMapper;
