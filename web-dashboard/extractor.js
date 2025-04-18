/**
 * PhishShield Email Content Extractor
 * Professional-grade extraction orchestrator with caching and optimization
 * Patterns inspired by VirusTotal and Google's malware detection
 */

class EmailContentExtractor {
  constructor() {
    this.cache = new CacheManager(1000 * 60 * 15); // 15 min cache
    this.extractionQueue = [];
    this.isProcessing = false;
  }

  /**
   * Orchestrate complete email content extraction
   * Returns structured data similar to VirusTotal analysis format
   */
  async extractComplete(emailData) {
    const cacheKey = this.generateCacheKey(emailData);
    const cached = this.cache.get(cacheKey);
    
    if (cached) {
      return cached;
    }

    try {
      const extraction = await this.performExtraction(emailData);
      
      // Verify we got valid data, not an error object
      if (extraction && extraction.error === true) {
        throw new Error(extraction.message || 'Unknown extraction error');
      }
      
      this.cache.set(cacheKey, extraction);
      return extraction;
    } catch (error) {
      console.error('Extraction failed:', error);
      throw error; // Properly throw so caller can catch
    }
  }

  /**
   * Perform extraction with optimized parallel processing
   */
  async performExtraction(emailData) {
    const { subject = '', body = '', sender = '', replyTo = '', urls = [] } = emailData;

    const startTime = performance.now();

    // Parallel extraction tasks (non-blocking)
    const [
      urlData,
      emailAddresses,
      ipAddresses,
      serverInfo,
      suspiciousPatterns,
      headerAnalysis
    ] = await Promise.all([
      this.extractURLsOptimized(body, urls),
      this.extractEmailsOptimized(body),
      this.extractIPsOptimized(body),
      this.extractServerInfoOptimized(body),
      this.extractSuspiciousPatternsOptimized(body),
      this.analyzeHeadersOptimized(subject, sender, replyTo, body)
    ]);

    const processingTime = performance.now() - startTime;

    return {
      // Metadata
      metadata: {
        extractionTimestamp: new Date().toISOString(),
        processingTimeMs: processingTime,
        contentSize: body.length,
        extractionVersion: '2.0'
      },

      // Core findings
      urls: urlData,
      emails: emailAddresses,
      ips: ipAddresses,
      
      // Server/Infrastructure intelligence
      infrastructure: serverInfo,
      
      // Content analysis
      suspiciousContent: suspiciousPatterns,
      headerIntelligence: headerAnalysis,
      
      // Risk scoring components
      riskFactors: this.calculateRiskFactors(
        urlData,
        emailAddresses,
        headerAnalysis,
        suspiciousPatterns
      ),
      
      // Forensic summary
      forensics: this.generateForensicsSummary(
        urlData,
        emailAddresses,
        ipAddresses,
        suspiciousPatterns,
        headerAnalysis
      )
    };
  }

  /**
   * Extract and analyze URLs with categorization
   */
  async extractURLsOptimized(body, providedUrls = []) {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        try {
          if (!TextExtractor) {
            throw new Error('TextExtractor not available');
          }
          
          const extracted = TextExtractor.extractURLs(body);
          
          // Merge with provided URLs
          const provided = providedUrls.map(url => ({
            url: TextExtractor.normalizeURL(url),
            raw: url,
            domain: this.extractDomain(url),
            protocol: TextExtractor.isValidURL(url) ? new URL(TextExtractor.normalizeURL(url)).protocol : 'unknown',
            isSuspicious: TextExtractor.isSuspiciousURL(url),
            extractionMethod: 'provided',
            source: 'user_input'
          }));

          // Deduplicate and merge
          const urlMap = new Map();
          [...extracted, ...provided].forEach(urlData => {
            const key = urlData.domain;
            if (!urlMap.has(key)) {
              urlMap.set(key, urlData);
            }
          });

          resolve({
            count: urlMap.size,
            unique_domains: urlMap.size,
            urls: Array.from(urlMap.values()),
            summary: {
              shortened_urls: Array.from(urlMap.values()).filter(u => u.extractionMethod === 'shortened').length,
              ip_based: Array.from(urlMap.values()).filter(u => u.extractionMethod === 'ip_based').length,
              encoded: Array.from(urlMap.values()).filter(u => u.extractionMethod === 'encoded').length,
              suspicious_count: Array.from(urlMap.values()).filter(u => u.isSuspicious).length
            }
          });
        } catch (error) {
          console.error('URL extraction error:', error);
          reject(error);
        }
      }, 0);
    });
  }

  /**
   * Extract and classify email addresses
   */
  async extractEmailsOptimized(body) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const emails = TextExtractor.extractEmails(body);
        
        const classified = {
          count: emails.length,
          by_type: {
            freemail: emails.filter(e => TextExtractor.isFreemailProvider(e.email)).length,
            corporate: emails.filter(e => !TextExtractor.isFreemailProvider(e.email)).length,
            suspicious_domain: emails.filter(e => e.isSuspicious).length
          },
          emails: emails,
          unique_domains: [...new Set(emails.map(e => e.domain))]
        };

        resolve(classified);
      }, 0);
    });
  }

  /**
   * Extract IP addresses with classification
   */
  async extractIPsOptimized(body) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const ips = TextExtractor.extractIPAddresses(body);
        
        const classified = {
          count: ips.length,
          by_type: {},
          ips: ips
        };

        // Count by type
        ips.forEach(ipData => {
          classified.by_type[ipData.type] = (classified.by_type[ipData.type] || 0) + 1;
        });

        resolve(classified);
      }, 0);
    });
  }

  /**
   * Extract server and infrastructure information
   */
  async extractServerInfoOptimized(body) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const serverInfo = TextExtractor.extractServerInfo(body);
        
        resolve({
          dns_records: serverInfo.dnsRecords.length,
          ipv6_addresses: serverInfo.ipv6Addresses.length,
          mac_addresses: serverInfo.macAddresses.length,
          ports_detected: serverInfo.ports.length,
          data: serverInfo
        });
      }, 0);
    });
  }

  /**
   * Extract suspicious content patterns
   */
  async extractSuspiciousPatternsOptimized(body) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const patterns = TextExtractor.extractSuspiciousPatterns(body);
        const riskScore = this.calculatePatternRisk(patterns);
        
        resolve({
          patterns: patterns,
          risk_level: riskScore.level,
          risk_score: riskScore.score,
          red_flags: this.identifyRedFlags(patterns)
        });
      }, 0);
    });
  }

  /**
   * Analyze email headers for spoofing and forgery
   */
  async analyzeHeadersOptimized(subject, sender, replyTo, body) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const headers = TextExtractor.parseEmailHeaders(subject, sender, replyTo, body);
        
        resolve({
          subject_analysis: headers.subject,
          sender_analysis: headers.sender,
          reply_to_analysis: headers.replyTo,
          authentication_issues: headers.headerFlags,
          spoofing_risk: this.calculateSpoofingRisk(headers),
          alignment_issues: this.checkAuthenticationAlignment(headers)
        });
      }, 0);
    });
  }

  /**
   * Calculate risk factors from extracted data
   */
  calculateRiskFactors(urls, emails, headers, suspicious) {
    const factors = [];

    // URL risks
    if (urls.summary.shortened_urls > 0) {
      factors.push({
        category: 'URL_RISK',
        severity: 'medium',
        description: `${urls.summary.shortened_urls} shortened URL(s) detected`,
        weight: 0.15
      });
    }

    if (urls.summary.ip_based > 0) {
      factors.push({
        category: 'URL_RISK',
        severity: 'high',
        description: 'IP-based URL(s) detected instead of domain names',
        weight: 0.25
      });
    }

    if (urls.summary.suspicious_count > 0) {
      factors.push({
        category: 'URL_RISK',
        severity: 'high',
        description: `${urls.summary.suspicious_count} suspicious URL pattern(s)`,
        weight: 0.20
      });
    }

    // Email risks
    if (headers.sender_analysis.isFreeMail) {
      factors.push({
        category: 'SENDER_RISK',
        severity: 'medium',
        description: 'Sender uses free email provider',
        weight: 0.10
      });
    }

    if (headers.sender_analysis.hasHomograph) {
      factors.push({
        category: 'SENDER_RISK',
        severity: 'critical',
        description: 'Homograph/lookalike domain detected',
        weight: 0.30
      });
    }

    if (headers.sender_analysis.domainMismatchReplyTo) {
      factors.push({
        category: 'AUTH_RISK',
        severity: 'high',
        description: 'Sender domain mismatches Reply-To domain',
        weight: 0.20
      });
    }

    // Header risks
    Object.entries(headers.authentication_issues).forEach(([key, value]) => {
      if (value === true) {
        factors.push({
          category: 'AUTH_RISK',
          severity: 'high',
          description: `Missing/suspicious: ${key}`,
          weight: 0.15
        });
      }
    });

    // Content risks
    if (suspicious.patterns.passwords > 0 || suspicious.patterns.creditCards > 0) {
      factors.push({
        category: 'CREDENTIAL_RISK',
        severity: 'critical',
        description: 'Requests for sensitive credentials detected',
        weight: 0.40
      });
    }

    if (suspicious.patterns.urgencyLanguage > 0) {
      factors.push({
        category: 'SOCIAL_ENG_RISK',
        severity: 'high',
        description: 'Urgency/pressure tactics detected',
        weight: 0.15
      });
    }

    return factors;
  }

  /**
   * Generate forensic intelligence summary
   */
  generateForensicsSummary(urls, emails, ips, suspicious, headers) {
    return {
      domains_count: urls.unique_domains,
      external_ips: ips.count,
      email_addresses: emails.count,
      risk_indicators: {
        brand_impersonation: this.detectBrandImpersonation(urls, headers),
        credential_harvesting: (suspicious.patterns.passwords || 0) + (suspicious.patterns.creditCards || 0),
        urgent_language: suspicious.patterns.urgencyLanguage,
        payment_requests: suspicious.patterns.paymentRequests,
        authentication_abuse: Object.values(headers.authentication_issues).filter(v => v === true).length
      },
      infrastructure_insight: {
        uses_ip_addresses: ips.count > 0,
        hosting_provider_risk: this.analyzeHostingRisk(ips),
        domain_age_risk: this.analyzeDomainAgeRisk(urls.urls),
        subdomain_abuse: urls.urls.filter(u => (u.domain.match(/\./g) || []).length > 1).length
      }
    };
  }

  /**
   * Calculate pattern-based risk
   */
  calculatePatternRisk(patterns) {
    let score = 0;
    let level = 'low';

    if ((patterns.securityQuestions || 0) > 0) score += 25;
    if ((patterns.accountActivation || 0) > 0) score += 15;
    if ((patterns.passwords || 0) > 0) score += 30;
    if ((patterns.creditCards || 0) > 0) score += 40;
    if ((patterns.paymentRequests || 0) > 0) score += 20;
    if ((patterns.urgencyLanguage || 0) > 0) score += 10;

    if (score >= 60) level = 'critical';
    else if (score >= 40) level = 'high';
    else if (score >= 20) level = 'medium';

    return { score: Math.min(score, 100), level };
  }

  /**
   * Identify specific red flags
   */
  identifyRedFlags(patterns) {
    const flags = [];

    if (patterns.passwords > 0) flags.push('Password request detected');
    if (patterns.creditCards > 0) flags.push('Financial credential request');
    if (patterns.urgencyLanguage > 0) flags.push('High-pressure tactics');
    if (patterns.securityQuestions > 0) flags.push('Security question requests');
    if (patterns.accountActivation > 0) flags.push('Account verification scam');
    if (patterns.paymentRequests > 0) flags.push('Unauthorized payment request');

    return flags;
  }

  /**
   * Calculate spoofing risk from headers
   */
  calculateSpoofingRisk(headers) {
    let risk = 'low';
    let score = 0;

    if (headers.sender.hasHomograph) {
      risk = 'critical';
      score = 95;
    } else if (headers.sender.domainMismatchReplyTo) {
      risk = 'high';
      score = 75;
    } else if (headers.headerFlags.missingReplyTo || headers.headerFlags.hiddenReplyTo) {
      risk = 'medium';
      score = 50;
    }

    return { risk, score };
  }

  /**
   * Check SPF/DKIM/DMARC alignment
   */
  checkAuthenticationAlignment(headers) {
    const issues = [];

    if (headers.headerFlags.suspiciousSPF) issues.push('SPF alignment failure');
    if (headers.headerFlags.suspiciousDKIM) issues.push('DKIM alignment failure');
    if (headers.headerFlags.multipleFromAddresses) issues.push('Multiple From addresses');

    return {
      aligned: issues.length === 0,
      issues: issues,
      authentication_score: Math.max(0, 100 - (issues.length * 30))
    };
  }

  /**
   * Detect brand impersonation
   */
  detectBrandImpersonation(urls, headers) {
    const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'bank'];
    let detected = [];

    urls.urls.forEach(u => {
      brands.forEach(brand => {
        if (u.domain.includes(brand)) detected.push(brand);
      });
    });

    brands.forEach(brand => {
      if (headers.subject_analysis.suspiciousKeywords[brand]) {
        detected.push(brand);
      }
    });

    return [... new Set(detected)];
  }

  /**
   * Analyze hosting provider risk
   */
  analyzeHostingRisk(ips) {
    // In production, check against threat intelligence databases
    const highRiskProviders = ['datacenter grade IP', 'bulletproof hosting'];
    return ips.ips.some(ip => highRiskProviders.includes(ip.type)) ? 'high' : 'medium';
  }

  /**
   * Analyze domain age risk (simulated)
   */
  analyzeDomainAgeRisk(urls) {
    // In production, query WHOIS data
    return urls.length > 0 ? 'medium' : 'low';
  }

  /**
   * Extract domain safely
   */
  extractDomain(url) {
    try {
      return new URL(TextExtractor.isValidURL(url) ? 
        TextExtractor.normalizeURL(url) : 
        'https://' + url).hostname;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Generate unique cache key
   */
  generateCacheKey(emailData) {
    const hashString = JSON.stringify(emailData);
    let hash = 0;
    for (let i = 0; i < hashString.length; i++) {
      const char = hashString.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return `extraction_${Math.abs(hash)}`;
  }
}

// Export
window.EmailContentExtractor = EmailContentExtractor;
