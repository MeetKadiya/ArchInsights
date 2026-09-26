import re
from typing import List, Dict, Tuple, Optional
from app.domain_scanner.models import TechDetection


class FingerprintEngine:
    """
    Technology stack fingerprinting engine that inspects HTTP response headers,
    cookies, meta tags, script URLs, and DOM markers.
    """

    def analyze(
        self,
        headers: Dict[str, str],
        cookies: List[str],
        html_body: str,
    ) -> Tuple[List[TechDetection], Dict[str, bool]]:
        """
        Analyzes HTTP headers, cookies, and HTML body to detect technologies
        and audit critical security headers.
        """
        detections: List[TechDetection] = []
        html_lower = html_body.lower() if html_body else ""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        cookies_lower = [c.lower() for c in cookies]

        # ---------------- 1. Cloud & CDN Detection ----------------
        server_hdr = headers_lower.get("server", "").lower()
        via_hdr = headers_lower.get("via", "").lower()

        # Cloudflare
        if "cf-ray" in headers_lower or "cloudflare" in server_hdr or "__cf_bm" in "".join(cookies_lower):
            detections.append(
                TechDetection(
                    name="Cloudflare",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: CF-Ray or Server: cloudflare"],
                    description="Global CDN, DDoS mitigation, and reverse proxy edge network.",
                )
            )

        # AWS CloudFront / S3 / ALB
        if "x-amz-cf-id" in headers_lower or "cloudfront" in via_hdr or "x-amz-request-id" in headers_lower:
            detections.append(
                TechDetection(
                    name="AWS CloudFront / AWS Edge",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: X-Amz-Cf-Id or CloudFront in Via"],
                    description="Amazon Web Services content delivery network and edge caching.",
                )
            )
        if any("awsalb" in c or "awsalbcors" in c for c in cookies_lower):
            detections.append(
                TechDetection(
                    name="AWS Application Load Balancer",
                    category="Cloud / CDN",
                    confidence=0.95,
                    indicators=["Cookie: AWSALB sticky session"],
                    description="AWS Elastic Load Balancing routing requests across backend targets.",
                )
            )

        # Fastly
        if "fastly-debug-digest" in headers_lower or "fastly" in via_hdr or "x-fastly-request-id" in headers_lower:
            detections.append(
                TechDetection(
                    name="Fastly CDN",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: Fastly request headers"],
                    description="Edge cloud and real-time content delivery network.",
                )
            )

        # Akamai
        if "x-akamai-transformed" in headers_lower or "akamai" in server_hdr:
            detections.append(
                TechDetection(
                    name="Akamai CDN",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: X-Akamai-Transformed"],
                    description="Enterprise content delivery and cybersecurity platform.",
                )
            )

        # Vercel
        if "x-vercel-id" in headers_lower or "vercel" in server_hdr:
            detections.append(
                TechDetection(
                    name="Vercel Edge Platform",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: X-Vercel-Id"],
                    description="Frontend cloud platform optimized for Next.js and serverless deployments.",
                )
            )

        # Netlify
        if "x-nf-request-id" in headers_lower or "netlify" in server_hdr:
            detections.append(
                TechDetection(
                    name="Netlify",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: X-NF-Request-Id"],
                    description="Hosting and serverless backend platform for web applications.",
                )
            )

        # Google Cloud / Firebase
        if "x-goog-generation" in headers_lower or "firebase" in html_lower or "google frontend" in server_hdr:
            detections.append(
                TechDetection(
                    name="Google Cloud Platform",
                    category="Cloud / CDN",
                    confidence=0.9,
                    indicators=["Header: Server Google Frontend or GCP Storage"],
                    description="Google Cloud infrastructure and edge load balancer.",
                )
            )

        # Azure
        if "x-azure-ref" in headers_lower or "azurewebsites.net" in html_lower:
            detections.append(
                TechDetection(
                    name="Microsoft Azure",
                    category="Cloud / CDN",
                    confidence=1.0,
                    indicators=["Header: X-Azure-Ref"],
                    description="Microsoft Azure cloud application gateway & hosting.",
                )
            )

        # ---------------- 2. Web Servers & Proxies ----------------
        if "nginx" in server_hdr:
            ver = self._extract_version(server_hdr, r"nginx/([0-9.]+)")
            detections.append(
                TechDetection(
                    name="Nginx",
                    category="Web Server",
                    confidence=1.0,
                    version=ver,
                    indicators=[f"Server header: {server_hdr}"],
                    description="High-performance HTTP server, reverse proxy, and load balancer.",
                )
            )
        elif "apache" in server_hdr:
            ver = self._extract_version(server_hdr, r"apache/([0-9.]+)")
            detections.append(
                TechDetection(
                    name="Apache HTTP Server",
                    category="Web Server",
                    confidence=1.0,
                    version=ver,
                    indicators=[f"Server header: {server_hdr}"],
                    description="Open-source modular HTTP web server.",
                )
            )
        elif "caddy" in server_hdr:
            detections.append(
                TechDetection(
                    name="Caddy Web Server",
                    category="Web Server",
                    confidence=1.0,
                    indicators=[f"Server header: {server_hdr}"],
                    description="Modern, enterprise-ready web server with automatic HTTPS.",
                )
            )
        elif "envoy" in server_hdr or "envoy" in headers_lower.get("x-envoy-upstream-service-time", ""):
            detections.append(
                TechDetection(
                    name="Envoy Proxy",
                    category="Web Server",
                    confidence=1.0,
                    indicators=["Envoy upstream header"],
                    description="Cloud-native high-performance edge and service proxy.",
                )
            )
        elif "litespeed" in server_hdr:
            detections.append(
                TechDetection(
                    name="LiteSpeed Web Server",
                    category="Web Server",
                    confidence=1.0,
                    indicators=[f"Server header: {server_hdr}"],
                    description="High-performance, lightweight Apache-compatible web server.",
                )
            )
        elif "microsoft-iis" in server_hdr:
            ver = self._extract_version(server_hdr, r"microsoft-iis/([0-9.]+)")
            detections.append(
                TechDetection(
                    name="Microsoft IIS",
                    category="Web Server",
                    confidence=1.0,
                    version=ver,
                    indicators=[f"Server header: {server_hdr}"],
                    description="Windows Server Internet Information Services web platform.",
                )
            )

        elif "gws" in server_hdr or "gse" in server_hdr or "esf" in server_hdr:
            detections.append(
                TechDetection(
                    name="Google Web Server (GWS)",
                    category="Web Server",
                    confidence=1.0,
                    indicators=[f"Server header: {server_hdr}"],
                    description="Google proprietary high-performance web server and reverse proxy.",
                )
            )

        # ---------------- 3. Backend Runtimes & Frameworks ----------------
        powered_by = headers_lower.get("x-powered-by", "").lower()

        # Express / Node.js
        if "express" in powered_by or any("connect.sid" in c for c in cookies_lower):
            detections.append(
                TechDetection(
                    name="Node.js / Express",
                    category="Backend Runtime",
                    confidence=0.95,
                    indicators=["Header: X-Powered-By Express or Cookie: connect.sid"],
                    description="Asynchronous event-driven JavaScript backend framework.",
                )
            )

        # Next.js Server
        if "next.js" in powered_by or "__next_data__" in html_lower or "/_next/static/" in html_lower:
            detections.append(
                TechDetection(
                    name="Next.js",
                    category="Frontend Framework",
                    confidence=1.0,
                    indicators=["HTML: __NEXT_DATA__ hydration script or /_next/ path"],
                    description="Production React framework for full-stack web applications.",
                )
            )

        # Python (Django / FastAPI / Flask)
        if any("csrftoken" in c or "sessionid" in c for c in cookies_lower) and ("csrfmiddlewaretoken" in html_lower or "django" in "".join(cookies_lower)):
            detections.append(
                TechDetection(
                    name="Python / Django",
                    category="Backend Runtime",
                    confidence=0.9,
                    indicators=["Cookie: csrftoken and Django csrfmiddlewaretoken"],
                    description="Python high-level web framework for rapid development.",
                )
            )
        elif "fastapi" in powered_by or "/docs#/default/" in html_lower:
            detections.append(
                TechDetection(
                    name="FastAPI",
                    category="Backend Runtime",
                    confidence=0.9,
                    indicators=["FastAPI swagger UI markers"],
                    description="High performance, modern Python API framework with OpenAPI.",
                )
            )

        # PHP & Laravel
        if "php" in powered_by or any("phpsessid" in c for c in cookies_lower):
            ver = self._extract_version(powered_by, r"php/([0-9.]+)")
            detections.append(
                TechDetection(
                    name="PHP",
                    category="Backend Runtime",
                    confidence=1.0,
                    version=ver,
                    indicators=["Header: X-Powered-By PHP or Cookie: PHPSESSID"],
                    description="General-purpose server-side scripting language.",
                )
            )
        if any("laravel_session" in c or "xsrf-token" in c for c in cookies_lower) and "laravel" in html_lower:
            detections.append(
                TechDetection(
                    name="Laravel Framework",
                    category="Backend Runtime",
                    confidence=0.95,
                    indicators=["Cookie: laravel_session"],
                    description="PHP web application framework with expressive syntax.",
                )
            )

        # ASP.NET
        if "asp.net" in powered_by or "x-aspnet-version" in headers_lower or any("asp.net_sessionid" in c for c in cookies_lower):
            ver = headers_lower.get("x-aspnet-version")
            detections.append(
                TechDetection(
                    name="ASP.NET / .NET Core",
                    category="Backend Runtime",
                    confidence=1.0,
                    version=ver,
                    indicators=["Header: X-AspNet-Version or ASP.NET_SessionId cookie"],
                    description="Enterprise web application framework built on Microsoft .NET.",
                )
            )

        # Java / Spring
        if any("jsessionid" in c for c in cookies_lower):
            detections.append(
                TechDetection(
                    name="Java / Spring Boot",
                    category="Backend Runtime",
                    confidence=0.85,
                    indicators=["Cookie: JSESSIONID standard Java servlet container cookie"],
                    description="Enterprise Java servlet / Spring framework container.",
                )
            )

        # ---------------- 4. CMS (Content Management Systems) ----------------
        if "/wp-content/" in html_lower or "/wp-includes/" in html_lower or 'content="wordpress' in html_lower:
            ver = self._extract_meta_generator(html_body, r"wordpress ([0-9.]+)")
            detections.append(
                TechDetection(
                    name="WordPress CMS",
                    category="CMS",
                    confidence=1.0,
                    version=ver,
                    indicators=["Path: /wp-content/ or meta generator WordPress"],
                    description="World's most popular open-source content management system.",
                )
            )

        if "shopify.theme" in html_lower or "cdn.shopify.com" in html_lower:
            detections.append(
                TechDetection(
                    name="Shopify",
                    category="CMS",
                    confidence=1.0,
                    indicators=["Script domain: cdn.shopify.com"],
                    description="Global multi-channel cloud commerce platform.",
                )
            )

        if "drupal.settings" in html_lower or "/sites/default/files" in html_lower or 'content="drupal' in html_lower:
            detections.append(
                TechDetection(
                    name="Drupal CMS",
                    category="CMS",
                    confidence=0.95,
                    indicators=["Drupal settings script object"],
                    description="Flexible enterprise open-source digital experience platform.",
                )
            )

        if "data-wf-page" in html_lower or "data-wf-site" in html_lower or "webflow.js" in html_lower:
            detections.append(
                TechDetection(
                    name="Webflow",
                    category="CMS",
                    confidence=1.0,
                    indicators=["Attribute: data-wf-page or webflow.js"],
                    description="Visual web development CMS and hosting platform.",
                )
            )

        if "ghost-version" in headers_lower or 'content="ghost' in html_lower or "/ghost/api/" in html_lower or "ghost-sdk" in html_lower or "ghost.min.js" in html_lower:
            detections.append(
                TechDetection(
                    name="Ghost CMS",
                    category="CMS",
                    confidence=0.95,
                    indicators=["Ghost meta tags or ghost-version header"],
                    description="Modern open-source publishing platform built on Node.js.",
                )
            )

        # ---------------- 5. Frontend Frameworks & Libraries ----------------
        # React (if not already captured as Next.js)
        if "_reactrootcontainer" in html_lower or "react-dom" in html_lower or "data-reactroot" in html_lower:
            if not any(d.name == "Next.js" for d in detections):
                detections.append(
                    TechDetection(
                        name="React",
                        category="Frontend Framework",
                        confidence=0.95,
                        indicators=["DOM: data-reactroot or react-dom runtime"],
                        description="Component-based declarative JavaScript UI library.",
                    )
                )

        # Vue / Nuxt
        if "__nuxt__" in html_lower:
            detections.append(
                TechDetection(
                    name="Nuxt.js",
                    category="Frontend Framework",
                    confidence=1.0,
                    indicators=["DOM: __NUXT__ hydration object"],
                    description="Intuitive Vue.js full-stack framework.",
                )
            )
        elif "data-v-" in html_lower or "v-cloak" in html_lower or "vue.min.js" in html_lower:
            detections.append(
                TechDetection(
                    name="Vue.js",
                    category="Frontend Framework",
                    confidence=0.95,
                    indicators=["DOM: data-v- scoped attribute or Vue runtime"],
                    description="Progressive reactive JavaScript framework for user interfaces.",
                )
            )

        # Angular
        if "ng-version" in html_lower or "ng-app" in html_lower:
            ver = self._extract_version(html_body, r'ng-version="([0-9.]+)"')
            detections.append(
                TechDetection(
                    name="Angular",
                    category="Frontend Framework",
                    confidence=1.0,
                    version=ver,
                    indicators=["DOM: ng-version attribute"],
                    description="Google TypeScript-based component application platform.",
                )
            )

        # Svelte
        if "svelte" in html_lower or "__svelte" in html_lower:
            detections.append(
                TechDetection(
                    name="Svelte",
                    category="Frontend Framework",
                    confidence=0.9,
                    indicators=["Svelte class names or runtime identifiers"],
                    description="Compiler-driven reactive component web framework.",
                )
            )

        # Tailwind CSS
        if re.search(r'class="[^"]*(?:flex|grid|hidden|text-sm|bg-|p-|m-)[^"]*"', html_body):
            detections.append(
                TechDetection(
                    name="Tailwind CSS",
                    category="Frontend Framework",
                    confidence=0.9,
                    indicators=["HTML utility classes matching Tailwind CSS design tokens"],
                    description="Utility-first CSS framework for rapid modern UI development.",
                )
            )

        # Bootstrap
        if "bootstrap.min.css" in html_lower or "bootstrap.bundle" in html_lower:
            detections.append(
                TechDetection(
                    name="Bootstrap",
                    category="Frontend Framework",
                    confidence=0.95,
                    indicators=["Script/Link: bootstrap.min.css/js"],
                    description="Popular responsive CSS component framework.",
                )
            )

        # jQuery
        if "jquery.min.js" in html_lower or "jquery-" in html_lower:
            detections.append(
                TechDetection(
                    name="jQuery",
                    category="Frontend Framework",
                    confidence=0.9,
                    indicators=["Script: jquery.min.js"],
                    description="Legacy fast, small, and feature-rich JavaScript DOM library.",
                )
            )

        # ---------------- 6. Third-Party APIs, Analytics & SaaS ----------------
        if "google-analytics.com" in html_lower or "googletagmanager.com/gtag/js" in html_lower or any("_ga" in c for c in cookies_lower):
            detections.append(
                TechDetection(
                    name="Google Analytics / GTM",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: Google Tag Manager or _ga analytics cookie"],
                    description="Web traffic tracking, conversion analytics, and tag management.",
                )
            )

        if "js.stripe.com" in html_lower:
            detections.append(
                TechDetection(
                    name="Stripe Payments",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: js.stripe.com v3 client"],
                    description="Secure online payment processing and subscription billing API.",
                )
            )

        if "paypal.com/sdk" in html_lower:
            detections.append(
                TechDetection(
                    name="PayPal Checkout",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: paypal.com/sdk"],
                    description="Global digital payment processing checkout integration.",
                )
            )

        if "sentry.io" in html_lower or "browser.sentry-cdn.com" in html_lower:
            detections.append(
                TechDetection(
                    name="Sentry Error Monitoring",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: sentry-cdn.com SDK"],
                    description="Application performance monitoring and error logging platform.",
                )
            )

        if "cdn.segment.com" in html_lower or "analytics.js" in html_lower and "segment" in html_lower:
            detections.append(
                TechDetection(
                    name="Segment Customer Data Platform",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: cdn.segment.com/analytics.js"],
                    description="Unified customer data pipeline and event streaming API.",
                )
            )

        if "intercom.io" in html_lower or "widget.intercom.io" in html_lower:
            detections.append(
                TechDetection(
                    name="Intercom Live Chat",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: widget.intercom.io"],
                    description="Customer messaging, conversational AI, and support suite.",
                )
            )

        if "recaptcha" in html_lower or "google.com/recaptcha" in html_lower:
            detections.append(
                TechDetection(
                    name="Google reCAPTCHA",
                    category="Security",
                    confidence=1.0,
                    indicators=["Script: google.com/recaptcha/api.js"],
                    description="Bot prevention and human verification security service.",
                )
            )

        if "challenges.cloudflare.com/turnstile" in html_lower:
            detections.append(
                TechDetection(
                    name="Cloudflare Turnstile",
                    category="Security",
                    confidence=1.0,
                    indicators=["Script: challenges.cloudflare.com/turnstile"],
                    description="Privacy-preserving CAPTCHA alternative and challenge API.",
                )
            )

        if "auth0.com" in html_lower or "cdn.auth0.com" in html_lower:
            detections.append(
                TechDetection(
                    name="Auth0 (Okta)",
                    category="Third-Party API",
                    confidence=1.0,
                    indicators=["Script: auth0-spa-js or auth0 domain"],
                    description="Universal enterprise authentication and authorization platform.",
                )
            )

        # ---------------- 7. Security Headers Audit ----------------
        sec_headers = {
            "strict-transport-security": "strict-transport-security" in headers_lower,
            "content-security-policy": "content-security-policy" in headers_lower,
            "x-frame-options": "x-frame-options" in headers_lower,
            "x-content-type-options": "x-content-type-options" in headers_lower,
            "referrer-policy": "referrer-policy" in headers_lower,
            "permissions-policy": "permissions-policy" in headers_lower,
        }

        # Deduplicate detections by name
        unique_detections: Dict[str, TechDetection] = {}
        for d in detections:
            if d.name not in unique_detections or d.confidence > unique_detections[d.name].confidence:
                unique_detections[d.name] = d

        return list(unique_detections.values()), sec_headers

    def _extract_version(self, text: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_meta_generator(self, html: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else None
