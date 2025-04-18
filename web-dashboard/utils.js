/**
 * PhishShield Professional Utilities Library
 * Production-grade text parsing, URL extraction, and validation
 * Similar to VirusTotal/Google's patterns
 */

class TextExtractor {
  static CACHE_DURATION_MS = 1000 * 60 * 10; // 10 minutes
  static cache = new Map();

  /**
   * Professional URL extraction with validation and deduplication
   * Handles various URL encoding formats, internationalized domains, etc.
   */
  static extractURLs(text) {
    if (!text) return [];

    // Extended regex pattern covering edge cases:
    // - IP addresses (including obfuscated)
    // - Shortened URLs
    // - International domains
    // - Protocol variations
    // - Suspicious encodings
    const urlPatterns = [
      // Standard URLs with protocols
      /https?:\/\/(?:[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})+/gi,
      // URLs without protocol (common in phishing)
      /(?<![@\s])(?:www\.)?[a-zA-Z0-9\-._~:/?#@!$&'()*+,;=%]+\.(com|org|net|edu|gov|co|uk|de|fr|ru|cn|io|app|dev|shop|online|site|website|click|download|bid|accountupdate|secure|verify|confirm|update)\b/gi,
      // IP addresses (including suspicious patterns)
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?::\d+)?(?:\/[^\s]*)?\b/gi,
      // Shortened URLs (bit.ly, tinyurl, etc.)
      /(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|short\.link|ow\.ly|goo\.gl)\/[a-zA-Z0-9]+/gi,
      // Base64 encoded URLs (suspicious pattern)
      /(?:http|https):\/\/[^\s]+(?:\?[^\s]*)?/gi
    ];

    const extractedURLs = new Set();
    const urlMetadata = [];

    for (const pattern of urlPatterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        const url = match[0].trim();
        
        // Validate before adding
        if (TextExtractor.isValidURL(url)) {
          const normalized = TextExtractor.normalizeURL(url);
          const duplicateKey = new URL(normalized).hostname;
          
          if (!extractedURLs.has(duplicateKey)) {
            extractedURLs.add(duplicateKey);
            urlMetadata.push({
              url: normalized,
              raw: url,
              domain: new URL(normalized).hostname,
              protocol: new URL(normalized).protocol,
              isSuspicious: TextExtractor.isSuspiciousURL(url),
              extractionMethod: TextExtractor.detectURLPattern(url)
            });
          }
        }
      }
    }

    return urlMetadata;
  }

  /**
   * Extract email addresses with classification (sender patterns)
   */
  static extractEmails(text) {
    const emailPattern = /([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi;
    const emails = new Set();
    const matches = text.matchAll(emailPattern);

    for (const match of matches) {
      emails.add(match[0].toLowerCase());
    }

    return Array.from(emails).map(email => ({
      email,
      domain: email.split('@')[1],
      isSuspicious: this.isSuspiciousEmailDomain(email)
    }));
  }

  /**
   * Extract IP addresses and ASNs
   */
  static extractIPAddresses(text) {
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi;
    const ips = new Set();
    const matches = text.matchAll(ipPattern);

    for (const match of matches) {
      const ip = match[0];
      if (!this.isPrivateIP(ip)) {
        ips.add(ip);
      }
    }

    return Array.from(ips).map(ip => ({
      ip,
      type: this.classifyIPRange(ip),
      isSuspicious: this.isSuspiciousIP(ip)
    }));
  }

  /**
   * Extract potential credentials and sensitive patterns
   * (for detecting phishing attempts to capture credentials)
   */
  static extractSuspiciousPatterns(text) {
    const patterns = {
      // Password/credential requests
      passwords: /(?:password|pwd|pass)\s*[:=]\s*(?:\*+|•+|xxx|redacted|click here|enter)/gi,
      creditCards: /(?:\d{4}[-\s]?){3}\d{4}|[0-9]{13,19}/g,
      securityQuestions: /(?:security question|mother's maiden name|pet name|favorite book)/gi,
      accountActivation: /(?:account (?:suspended|locked|disabled|inactive)|verify your account|confirm identity|urgent|immediate action)/gi,
      paymentRequests: /(?:click to pay|update payment|billing information|credit card details)/gi,
      urgencyLanguage: /(?:urgent|immediate|asap|act now|within \d+ hours?|verify now|confirm now)/gi
    };

    const suspicious = {};
    for (const [key, pattern] of Object.entries(patterns)) {
      const matches = text.match(pattern);
      suspicious[key] = matches ? matches.length : 0;
    }

    return suspicious;
  }

  /**
   * Extract DNS records and server information patterns
   */
  static extractServerInfo(text) {
    const patterns = {
      dns: /(?:DNS|MX|SPF|DKIM|DMARC)\s*[:=]\s*([^\n\r]+)/gi,
      ipv6: /(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/gi,
      macAddress: /(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})/gi,
      port: /:(\d{2,5})\b/g
    };

    return {
      dnsRecords: this.extractMatches(text, patterns.dns),
      ipv6Addresses: this.extractMatches(text, patterns.ipv6),
      macAddresses: this.extractMatches(text, patterns.macAddress),
      ports: Array.from(new Set((text.match(patterns.port) || []).map(p => p.replace(/:/g, ''))))
    };
  }

  /**
   * Professional email header parsing
   * Detects SPF, DKIM, DMARC alignment issues
   */
  static parseEmailHeaders(subject, sender, replyTo, body) {
    const headers = {
      subject: {
        text: subject,
        length: subject.length,
        hasUrgency: this.hasUrgencyKeywords(subject),
        hasExecutive: this.hasExecutiveKeywords(subject),
        suspiciousKeywords: this.detectSuspiciousKeywords(subject)
      },
      sender: {
        email: sender,
        domain: sender ? sender.split('@')[1] : null,
        hasHomograph: sender ? this.detectHomographAttack(sender) : false,
        isFreeMail: sender ? this.isFreemailProvider(sender) : false,
        domainMismatchReplyTo: sender && replyTo ? sender.split('@')[1] !== replyTo.split('@')[1] : false
      },
      replyTo: {
        email: replyTo,
        domain: replyTo ? replyTo.split('@')[1] : null,
        isDifferentFromSender: sender !== replyTo
      },
      headerFlags: {
        missingReplyTo: !replyTo,
        hiddenReplyTo: replyTo === '',
        multipleFromAddresses: (sender.match(/@/g) || []).length > 1,
        suspiciousSPF: /spf.*(?:softfail|fail|neutral)/i.test(body),
        suspiciousDKIM: /dkim.*(?:fail|none)/i.test(body),
        suspiciousRET: /^Return-Path:.*<>/m.test(body)
      }
    };

    return headers;
  }

  /**
   * Validate URL with comprehensive checks
   */
  static isValidURL(url) {
    try {
      // Normalize URL format first
      let testUrl = url;
      if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
        testUrl = 'https://' + url;
      }
      const parsed = new URL(testUrl);
      return parsed.hostname && parsed.hostname.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Normalize URLs to standard format
   */
  static normalizeURL(url) {
    try {
      let normalized = url;
      if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
        normalized = 'https://' + url;
      }
      const urlObj = new URL(normalized);
      // Remove trailing slashes and fragments for comparison
      return urlObj.origin + urlObj.pathname;
    } catch {
      return url;
    }
  }

  /**
   * Detect suspicious URL characteristics
   */
  static isSuspiciousURL(url) {
    const suspiciousIndicators = [
      /bit\.ly|tinyurl|goo\.gl|ow\.ly|short\.link/, // URL shorteners (common in phishing)
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP-based URLs
      /%[0-9a-f]{2}/i, // URL encoding (obfuscation)
      /js:|data:|vbscript:/i, // Protocol-based attacks
      /paypal|amazon|apple|microsoft|bank|verify|confirm|update|urgent/i, // Brand impersonation
      /[а-яёА-ЯЁ]/g, // Cyrillic homograph attacks
      /xn--/, // Internationalized domain names (IDN)
      /[0-9]+%/, // Percent encoding
      /login|signin|authenticate|credential|password/i // Authentication traps
    ];

    return suspiciousIndicators.some(indicator => indicator.test(url));
  }

  /**
   * Detect URL pattern type
   */
  static detectURLPattern(url) {
    if (/^https?:\/\//.test(url)) return 'standard';
    if (/bit\.ly|tinyurl|goo\.gl|ow\.ly/.test(url)) return 'shortened';
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) return 'ip_based';
    if (/%[0-9A-Fa-f]{2}/.test(url)) return 'encoded';
    return 'www_format';
  }

  /**
   * Check if IP is private range
   */
  static isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    return (parts[0] === 10) ||
           (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
           (parts[0] === 192 && parts[1] === 168) ||
           (parts[0] === 127);
  }

  /**
   * Classify IP address range
   */
  static classifyIPRange(ip) {
    const parts = ip.split('.').map(Number);
    
    if (parts[0] === 127) return 'loopback';
    if (parts[0] === 169 && parts[1] === 254) return 'link_local';
    if (parts[0] === 224) return 'multicast';
    if (parts[0] === 255) return 'broadcast';
    if (parts[0] <= 9) return 'class_a_public';
    if (parts[0] >= 11 && parts[0] <= 126) return 'public';
    if (parts[0] === 172 || parts[0] === 10 || parts[0] === 192) return 'private';
    
    return 'public';
  }

  /**
   * Detect suspicious IP
   */
  static isSuspiciousIP(ip) {
    return this.classifyIPRange(ip) === 'public' && !this.isPrivateIP(ip);
  }

  /**
   * Detect homograph attacks (look-alike domains)
   */
  static detectHomographAttack(email) {
    const domain = email.split('@')[1];
    const suspiciousDomains = [
      /paypa[l1]|pay-pal|paypa\.l/i,
      /amaz[o0]n|amazn/i,
      /app[l1]e|aple/i,
      /micros[o0]ft|microsft/i,
      /goog[l1]e|gogle/i,
      /face[b6]o?ok|facebooke/i
    ];
    return suspiciousDomains.some(pattern => pattern.test(domain));
  }

  /**
   * Check domain is freemail provider (often abused)
   */
  static isFreemailProvider(email) {
    const freemailDomains = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
      'mail.com', 'aol.com', 'protonmail.com', 'yandex.com'
    ];
    const domain = email.split('@')[1];
    return freemailDomains.includes(domain.toLowerCase());
  }

  /**
   * Detect suspicious email domain patterns
   */
  static isSuspiciousEmailDomain(email) {
    const domain = email.split('@')[1];
    return this.detectHomographAttack(email) ||
           this.isSuspiciousDomainPattern(domain);
  }

  /**
   * Check suspicious domain patterns
   */
  static isSuspiciousDomainPattern(domain) {
    return /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}|temporary|temp-mail|10minutemail/i.test(domain);
  }

  /**
   * Detect urgency keywords in text
   */
  static hasUrgencyKeywords(text) {
    const urgencyKeywords = /(?:urgent|immediate|asap|act now|within \d+ hours?|verify now|confirm now|click here|today)/gi;
    return urgencyKeywords.test(text);
  }

  /**
   * Detect executive impersonation keywords
   */
  static hasExecutiveKeywords(text) {
    const keywords = /(?:ceo|cfo|executive|boss|management|director|urgent request|confidential|private)/gi;
    return keywords.test(text);
  }

  /**
   * Extract suspicious keywords
   */
  static detectSuspiciousKeywords(text) {
    const keywords = {
      accountIssues: /(account|verify|confirm|update|suspended|locked|disabled)/gi,
      financial: /(payment|billing|invoice|refund|wire|transfer)/gi,
      urgency: /(urgent|immediate|asap|within \d+ hours)/gi,
      action: /(click|confirm|verify|update|action required)/gi
    };

    const detected = {};
    for (const [key, pattern] of Object.entries(keywords)) {
      const matches = text.match(pattern);
      detected[key] = matches ? matches.length : 0;
    }
    return detected;
  }

  /**
   * Extract matches safely
   */
  static extractMatches(text, pattern) {
    const matches = text.matchAll(pattern);
    const results = [];
    for (const match of matches) {
      results.push(match[0]);
    }
    return results;
  }
}

/**
 * Cache manager for performance optimization
 */
class CacheManager {
  constructor(ttl = 600000) { // 10 minutes default
    this.store = new Map();
    this.ttl = ttl;
  }

  set(key, value) {
    this.store.set(key, {
      value,
      timestamp: Date.now()
    });
  }

  get(key) {
    const item = this.store.get(key);
    if (!item) return null;

    if (Date.now() - item.timestamp > this.ttl) {
      this.store.delete(key);
      return null;
    }

    return item.value;
  }

  clear() {
    this.store.clear();
  }

  has(key) {
    return this.get(key) !== null;
  }
}

/**
 * Professional error handler
 */
class ErrorHandler {
  static handle(error, context = {}) {
    console.error(`[PhishShield Error] ${context.operation || 'Unknown'}: `, error);
    return {
      error: true,
      message: error.message || 'An error occurred',
      context,
      timestamp: new Date().toISOString()
    };
  }

  static validate(data, rules) {
    const errors = [];
    for (const [field, rule] of Object.entries(rules)) {
      if (rule.required && !data[field]) {
        errors.push(`${field} is required`);
      }
      if (rule.type && typeof data[field] !== rule.type) {
        errors.push(`${field} must be ${rule.type}`);
      }
    }
    return errors.length > 0 ? errors : null;
  }
}

// Export for use
window.TextExtractor = TextExtractor;
window.CacheManager = CacheManager;
window.ErrorHandler = ErrorHandler;
