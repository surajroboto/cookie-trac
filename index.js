// node index.js https://www.helix.com/

const { chromium } = require('playwright');
const fs = require('fs');

async function investigateCookies(websiteUrl) {
    console.log(`🔍 Investigating cookies on: ${websiteUrl}`);
    
    const browser = await chromium.launch({
        headless: false, // Set to true for headless mode
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu'
        ]
    });
    
    const context = await browser.newContext({
        // Accept all cookies and set user agent
        acceptDownloads: true,
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    });
    
    const page = await context.newPage();
    
    // Enable request/response logging
    const requests = [];
    const responses = [];
    
    page.on('request', request => {
        requests.push({
            url: request.url(),
            method: request.method(),
            headers: request.headers(),
            resourceType: request.resourceType()
        });
    });
    
    page.on('response', response => {
        responses.push({
            url: response.url(),
            status: response.status(),
            headers: response.headers(),
            fromCache: response.fromCache ? response.fromCache() : false
        });
    });
    
    try {
        // Navigate to the website with better error handling
        console.log('🌐 Loading website...');
        await page.goto(websiteUrl, { 
            waitUntil: 'domcontentloaded',
            timeout: 60000 
        });
        
        // Wait for any additional scripts to load
        console.log('⏳ Waiting for scripts and cookies to load...');
        await page.waitForTimeout(8000);
        
        // Try to trigger any lazy-loaded tracking scripts by scrolling
        await page.evaluate(() => {
            window.scrollTo(0, document.body.scrollHeight);
        });
        await page.waitForTimeout(2000);
        
        console.log('🍪 Analyzing cookies...');
        
        // Get all cookies
        const cookies = await context.cookies();
        
        console.log(`\n📊 Found ${cookies.length} cookies:`);
        console.log('=' .repeat(80));
        
        const cookieAnalysis = [];
        
        for (const cookie of cookies) {
            const analysis = {
                name: cookie.name,
                value: cookie.value,
                domain: cookie.domain,
                path: cookie.path,
                expires: cookie.expires ? new Date(cookie.expires * 1000).toISOString() : 'Session',
                httpOnly: cookie.httpOnly,
                secure: cookie.secure,
                sameSite: cookie.sameSite,
                size: cookie.value.length,
                suspicious: false,
                analysis: []
            };
            
            // Analyze for suspicious patterns
            const suspiciousPatterns = [
                { pattern: /track/i, reason: 'Contains "track" keyword' },
                { pattern: /analytics/i, reason: 'Contains "analytics" keyword' },
                { pattern: /pixel/i, reason: 'Contains "pixel" keyword' },
                { pattern: /fb/i, reason: 'Potentially Facebook related' },
                { pattern: /google|ga|gtag/i, reason: 'Potentially Google related' },
                { pattern: /doubleclick/i, reason: 'DoubleClick advertising' },
                { pattern: /adsystem/i, reason: 'Ad system related' },
                { pattern: /_utm/i, reason: 'UTM tracking parameter' },
                { pattern: /session.*id/i, reason: 'Session ID (check if expected)' }
            ];
            
            suspiciousPatterns.forEach(({ pattern, reason }) => {
                if (pattern.test(cookie.name) || pattern.test(cookie.value)) {
                    analysis.suspicious = true;
                    analysis.analysis.push(reason);
                }
            });
            
            // Check for long random values (potential tracking IDs)
            if (cookie.value.length > 20 && /^[a-zA-Z0-9+/=_-]+$/.test(cookie.value)) {
                analysis.suspicious = true;
                analysis.analysis.push('Long encoded value - potential tracking ID');
            }
            
            // Check for third-party domains
            const mainDomain = new URL(websiteUrl).hostname;
            if (!cookie.domain.includes(mainDomain) && !mainDomain.includes(cookie.domain.replace('.', ''))) {
                analysis.suspicious = true;
                analysis.analysis.push(`Third-party domain: ${cookie.domain}`);
            }
            
            cookieAnalysis.push(analysis);
            
            // Console output
            console.log(`\n🍪 Cookie: ${cookie.name}`);
            console.log(`   Value: ${cookie.value.substring(0, 50)}${cookie.value.length > 50 ? '...' : ''}`);
            console.log(`   Domain: ${cookie.domain}`);
            console.log(`   Path: ${cookie.path}`);
            console.log(`   Expires: ${analysis.expires}`);
            console.log(`   Secure: ${cookie.secure} | HttpOnly: ${cookie.httpOnly} | SameSite: ${cookie.sameSite}`);
            
            if (analysis.suspicious) {
                console.log(`   ⚠️  SUSPICIOUS: ${analysis.analysis.join(', ')}`);
            }
        }
        
        // Analyze requests for additional tracking
        console.log(`\n🌐 Network Analysis:`);
        console.log('=' .repeat(80));
        
        const trackingDomains = [
            'google-analytics.com',
            'googletagmanager.com',
            'doubleclick.net',
            'facebook.com',
            'connect.facebook.net',
            'hotjar.com',
            'mixpanel.com',
            'segment.com',
            'amplitude.com',
            'fullstory.com'
        ];
        
        const suspiciousRequests = requests.filter(req => 
            trackingDomains.some(domain => req.url.includes(domain)) ||
            req.url.includes('track') ||
            req.url.includes('analytics') ||
            req.url.includes('pixel')
        );
        
        console.log(`Found ${suspiciousRequests.length} potentially tracking-related requests:`);
        
        suspiciousRequests.forEach(req => {
            console.log(`   📡 ${req.method} ${req.url}`);
            console.log(`      Type: ${req.resourceType}`);
        });
        
        // Generate report
        const report = {
            website: websiteUrl,
            timestamp: new Date().toISOString(),
            totalCookies: cookies.length,
            suspiciousCookies: cookieAnalysis.filter(c => c.suspicious).length,
            cookies: cookieAnalysis,
            trackingRequests: suspiciousRequests,
            recommendations: generateRecommendations(cookieAnalysis, suspiciousRequests)
        };
        
        // Save report to file
        fs.writeFileSync(`cookie-report-${Date.now()}.json`, JSON.stringify(report, null, 2));
        
        console.log(`\n📋 Summary:`);
        console.log(`   Total cookies: ${report.totalCookies}`);
        console.log(`   Suspicious cookies: ${report.suspiciousCookies}`);
        console.log(`   Tracking requests: ${suspiciousRequests.length}`);
        console.log(`   Report saved to: cookie-report-${Date.now()}.json`);
        
        return report;
        
    } catch (error) {
        console.error('❌ Error during investigation:', error);
        throw error;
    } finally {
        await browser.close();
    }
}

function generateRecommendations(cookies, requests) {
    const recommendations = [];
    
    const suspiciousCookies = cookies.filter(c => c.suspicious);
    
    if (suspiciousCookies.length > 0) {
        recommendations.push('Review suspicious cookies and verify they are intentionally added');
        recommendations.push('Check if cookie consent mechanisms are properly implemented');
    }
    
    if (requests.length > 10) {
        recommendations.push('High number of tracking requests detected - consider auditing third-party scripts');
    }
    
    const thirdPartyCookies = cookies.filter(c => c.analysis.some(a => a.includes('Third-party domain')));
    if (thirdPartyCookies.length > 0) {
        recommendations.push('Third-party cookies detected - ensure GDPR/privacy compliance');
    }
    
    recommendations.push('Regularly audit cookies and tracking mechanisms');
    recommendations.push('Implement Content Security Policy (CSP) to control resource loading');
    
    return recommendations;
}

// Usage example
async function main() {
    const websiteUrl = process.argv[2] || 'https://your-website.com';
    
    if (!websiteUrl.startsWith('http')) {
        console.error('Please provide a valid URL starting with http:// or https://');
        process.exit(1);
    }
    
    try {
        await investigateCookies(websiteUrl);
    } catch (error) {
        console.error('Investigation failed:', error);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = { investigateCookies };