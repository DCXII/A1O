#!/usr/bin/env python3
"""
AIBrain - Intelligent OSINT Analysis Engine
Supports: Ollama (local, no API key) and Gemini (cloud, API key required).
"""

import json
import configparser
import hashlib
import pickle
import requests as http_requests
from pathlib import Path
from datetime import datetime, timedelta

# Try importing Gemini SDK
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


SYSTEM_PROMPT = """You are an elite OSINT (Open Source Intelligence) analyst.
You analyze raw data collected from public sources and provide actionable intelligence insights.
Your analysis should be:
- Precise and factual - only state what the data supports
- Structured with clear sections
- Focused on patterns, correlations, and actionable leads
- Professional in tone, like an intelligence agency brief
Never fabricate information. If data is insufficient, say so clearly.
Always note confidence levels (HIGH/MEDIUM/LOW) for each finding."""


class OllamaBackend:
    """Local AI backend using Ollama - no API key needed."""

    # Preferred models in order (best first)
    PREFERRED_MODELS = ['gemma3:4b', 'llama3.2:3b', 'phi3:3.8b', 'qwen2:1.5b', 'qwen2:0.5b']

    def __init__(self, base_url='http://localhost:11434', model=None, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.model = model
        self.available = False
        self._detect()

    def _log(self, msg, level='info'):
        if not self.verbose:
            return
        colors = {'info': '\033[94m', 'success': '\033[92m', 'warning': '\033[93m', 'error': '\033[91m'}
        end = '\033[0m'
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] {colors.get(level, '')}[OLLAMA] {msg}{end}")

    def _detect(self):
        """Detect Ollama and pick best available model."""
        try:
            r = http_requests.get(f"{self.base_url}/api/tags", timeout=3)
            if r.status_code != 200:
                self._log("Ollama not responding", 'warning')
                return
            models = [m['name'] for m in r.json().get('models', [])]
            if not models:
                self._log("Ollama running but no models installed", 'warning')
                return

            if self.model and any(self.model in m for m in models):
                # User specified a model that exists
                matching = [m for m in models if self.model in m]
                self.model = matching[0]
            else:
                # Auto-select best available
                self.model = None
                for preferred in self.PREFERRED_MODELS:
                    base_name = preferred.split(':')[0]
                    matching = [m for m in models if base_name in m]
                    if matching:
                        self.model = matching[0]
                        break
                if not self.model:
                    self.model = models[0]  # Fall back to whatever is available

            self.available = True
            self._log(f"Using model: {self.model}", 'success')
        except Exception as e:
            self._log(f"Ollama detection failed: {e}", 'warning')

    def generate(self, prompt):
        """Generate response from Ollama."""
        if not self.available:
            return None
        try:
            full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
            r = http_requests.post(
                f"{self.base_url}/api/generate",
                json={'model': self.model, 'prompt': full_prompt, 'stream': False},
                timeout=120
            )
            if r.status_code == 200:
                return r.json().get('response', '')
            self._log(f"Ollama error: {r.status_code}", 'error')
        except Exception as e:
            self._log(f"Ollama query failed: {e}", 'error')
        return None


class GeminiBackend:
    """Cloud AI backend using Google Gemini - requires API key."""

    def __init__(self, api_key, verbose=False):
        self.verbose = verbose
        self.available = False
        self.model = None
        self._init(api_key)

    def _log(self, msg, level='info'):
        if not self.verbose:
            return
        colors = {'info': '\033[94m', 'success': '\033[92m', 'warning': '\033[93m', 'error': '\033[91m'}
        end = '\033[0m'
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] {colors.get(level, '')}[GEMINI] {msg}{end}")

    def _init(self, api_key):
        if not GEMINI_AVAILABLE:
            self._log("google-generativeai not installed", 'warning')
            return
        if not api_key or api_key == 'YOUR_KEY_HERE':
            self._log("No API key configured", 'warning')
            return
        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(
                'gemini-2.0-flash',
                system_instruction=SYSTEM_PROMPT
            )
            self.available = True
            self._log("Gemini 2.0 Flash ready", 'success')
        except Exception as e:
            self._log(f"Init failed: {e}", 'error')

    def generate(self, prompt):
        if not self.available:
            return None
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            self._log(f"Query failed: {e}", 'error')
        return None


class AIBrain:
    """AI-powered intelligence analysis engine.
    
    Backends (auto-selected):
      1. Gemini (cloud) - if API key is set in config.ini
      2. Ollama (local) - if Ollama is running, no key needed
    
    Use --ai to enable auto-detection, --ai gemini or --ai ollama to force one.
    """

    def __init__(self, api_key=None, config_path='config.ini', cache_dir='.ai_cache',
                 backend='auto', ollama_model=None, verbose=False):
        self.verbose = verbose
        self.enabled = False
        self.backend = None
        self.backend_name = 'none'
        self.cache_dir = Path(cache_dir)
        self._init_backend(api_key, backend, ollama_model)

    def _log(self, msg, level='info'):
        if not self.verbose:
            return
        colors = {
            'info': '\033[94m', 'success': '\033[92m',
            'warning': '\033[93m', 'error': '\033[91m'
        }
        end = '\033[0m'
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] {colors.get(level, '')}[AI-BRAIN] {msg}{end}")

    def _init_backend(self, api_key, backend, ollama_model):
        """Initialize the best available AI backend."""
        if backend == 'gemini':
            # Force Gemini
            gb = GeminiBackend(api_key, self.verbose)
            if gb.available:
                self.backend = gb
                self.backend_name = 'gemini'
        elif backend == 'ollama':
            # Force Ollama
            ob = OllamaBackend(model=ollama_model, verbose=self.verbose)
            if ob.available:
                self.backend = ob
                self.backend_name = 'ollama'
        else:
            # Auto: try Gemini first, then Ollama
            gb = GeminiBackend(api_key, self.verbose)
            if gb.available:
                self.backend = gb
                self.backend_name = 'gemini'
            else:
                self._log("Gemini not available, trying Ollama (local)...", 'info')
                ob = OllamaBackend(model=ollama_model, verbose=self.verbose)
                if ob.available:
                    self.backend = ob
                    self.backend_name = 'ollama'

        if self.backend:
            self.cache_dir.mkdir(exist_ok=True)
            self.enabled = True
            self._log(f"AI Brain active - backend: {self.backend_name.upper()}", 'success')
        else:
            self._log("No AI backend available. AI features disabled.", 'warning')

    #   Cache  

    def _get_cache(self, key):
        cache_file = self.cache_dir / f"{hashlib.md5(key.encode()).hexdigest()}.cache"
        if cache_file.exists():
            try:
                with open(cache_file, 'rb') as f:
                    cached = pickle.load(f)
                if datetime.now() - cached['timestamp'] < timedelta(hours=6):
                    self._log("Cache hit", 'info')
                    return cached['data']
            except Exception:
                pass
        return None

    def _set_cache(self, key, data):
        cache_file = self.cache_dir / f"{hashlib.md5(key.encode()).hexdigest()}.cache"
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump({'data': data, 'timestamp': datetime.now()}, f)
        except Exception:
            pass

    def _query(self, prompt, cache_key=None):
        """Query the active backend with caching."""
        if not self.enabled:
            return None
        if cache_key:
            cached = self._get_cache(cache_key)
            if cached:
                return cached
        self._log(f"Querying {self.backend_name}...", 'info')
        result = self.backend.generate(prompt)
        if result and cache_key:
            self._set_cache(cache_key, result)
        return result

    #   Core Intelligence Methods  

    def analyze_profile(self, platform, raw_data):
        """Analyze raw scraped profile data and extract intelligence insights."""
        if not self.enabled or not raw_data:
            return None

        data_str = json.dumps(raw_data, indent=2, default=str)
        if len(data_str) > 8000:
            data_str = data_str[:8000] + "\n... [truncated]"

        prompt = f"""Analyze this {platform} profile data collected during an OSINT investigation.

RAW DATA:
```json
{data_str}
```

Provide a structured intelligence analysis:

1. **IDENTITY INDICATORS** - Real name, aliases, location, contact details
2. **BEHAVIORAL PATTERNS** - Activity patterns, interests, communities
3. **TECHNICAL FOOTPRINT** - Technologies, skill level, professional focus
4. **SOCIAL GRAPH** - Connections, affiliations, organizations
5. **NOTABLE FINDINGS** - High-value intelligence or leads
6. **SUGGESTED NEXT STEPS** - What to investigate next

Mark confidence as [HIGH], [MEDIUM], or [LOW] for each finding.
Be concise and actionable."""

        cache_key = f"profile_{platform}_{hashlib.md5(data_str[:500].encode()).hexdigest()}"
        result = self._query(prompt, cache_key)
        if result:
            self._log(f"Profile analysis done for {platform}", 'success')
        return result

    def correlate_findings(self, all_nodes):
        """Cross-correlate all gathered intelligence nodes."""
        if not self.enabled or not all_nodes:
            return None

        summary_parts = []
        for key, node in all_nodes.items():
            if node.get('results') and 'error' not in node.get('results', {}):
                entry = {
                    'type': node['type'],
                    'value': node['value'],
                    'confidence': node['confidence'],
                    'sources': node['sources'][:3],
                    'key_results': {}
                }
                results = node['results']
                if node['type'] == 'username':
                    platforms = results.get('platforms_found', [])
                    entry['key_results']['platforms'] = [p['platform'] for p in platforms[:15]]
                elif node['type'] == 'email':
                    entry['key_results']['deliverable'] = results.get('deliverable')
                    entry['key_results']['disposable'] = results.get('disposable')
                    entry['key_results']['gravatar'] = results.get('gravatar')
                elif node['type'] == 'domain':
                    entry['key_results']['ip'] = results.get('ip_address')
                    entry['key_results']['subdomains'] = len(results.get('subdomains', []))
                elif node['type'] == 'ip':
                    entry['key_results']['geo'] = results.get('geolocation')
                elif node['type'] == 'profile_url':
                    for pk in ['github', 'reddit', 'instagram', 'linkedin',
                               'medium', 'youtube', 'tiktok', 'twitch', 'facebook']:
                        if pk in results:
                            pdata = results[pk]
                            entry['key_results'][pk] = {'profile': pdata.get('profile', {})}
                            for lk in ['posts', 'articles', 'videos', 'repositories', 'comments']:
                                if lk in pdata:
                                    entry['key_results'][pk][f'{lk}_count'] = len(pdata[lk])
                elif node['type'] == 'person':
                    entry['key_results'] = results
                summary_parts.append(entry)

        data_str = json.dumps(summary_parts, indent=2, default=str)
        if len(data_str) > 12000:
            data_str = data_str[:12000] + "\n... [truncated]"

        prompt = f"""Cross-correlate this OSINT intelligence from multiple sources.

ALL INTELLIGENCE NODES:
```json
{data_str}
```

Analyze:
1. **IDENTITY RESOLUTION** - Connect data points belonging to same person/entity
2. **PATTERN ANALYSIS** - Behavioral patterns across sources
3. **NETWORK MAPPING** - Connections between entities
4. **RISK ASSESSMENT** - Privacy risks, exposed info, security concerns
5. **INTELLIGENCE GAPS** - What is still missing
6. **HIGH-VALUE LEADS** - Most promising further investigation leads

Be specific, reference actual data. Mark [HIGH], [MEDIUM], or [LOW] confidence."""

        cache_key = f"correlate_{hashlib.md5(data_str[:500].encode()).hexdigest()}"
        result = self._query(prompt, cache_key)
        if result:
            self._log("Cross-correlation complete", 'success')
        return result

    def extract_entities_intelligent(self, text, context_description=""):
        """AI-powered entity extraction beyond regex."""
        if not self.enabled or not text:
            return None

        text_sample = text[:4000] if len(text) > 4000 else text

        prompt = f"""Extract intelligence entities from this text. Context: {context_description}

TEXT:
\"\"\"{text_sample}\"\"\"

Return a JSON array. Each entity:
- "type": one of [email, username, person, domain, phone, organization, location, social_link, technology]
- "value": the extracted value  
- "confidence": HIGH/MEDIUM/LOW
- "context": why this is relevant

Return ONLY valid JSON array, nothing else. If none found, return []."""

        result = self._query(prompt)
        if result:
            try:
                json_str = result
                if '```' in json_str:
                    json_str = json_str.split('```')[1]
                    if json_str.startswith('json'):
                        json_str = json_str[4:]
                return json.loads(json_str.strip())
            except Exception:
                pass
        return None

    def generate_intelligence_report(self, nodes, statistics, correlation_analysis=None):
        """Generate AI-written intelligence brief."""
        if not self.enabled:
            return None

        findings = {}
        for key, node in nodes.items():
            ntype = node['type']
            if ntype not in findings:
                findings[ntype] = []
            entry = {
                'value': node['value'],
                'confidence': node['confidence'],
                'sources': node['sources'][:2],
                'results': {}
            }
            results = node.get('results', {})
            if results and 'error' not in results:
                # Strip AI analysis from results to keep prompt smaller
                entry['results'] = {k: v for k, v in results.items() if not k.startswith('_')}
            findings[ntype].append(entry)

        data_str = json.dumps({
            'statistics': statistics,
            'findings': findings
        }, indent=2, default=str)

        if len(data_str) > 15000:
            data_str = data_str[:15000] + "\n... [truncated]"

        correlation_section = ""
        if correlation_analysis:
            correlation_section = f"\nPREVIOUS CROSS-CORRELATION:\n{correlation_analysis[:3000]}\n"

        prompt = f"""Generate an OSINT intelligence report from this investigation data.

DATA:
```json
{data_str}
```
{correlation_section}

Write a professional report with these sections:
## EXECUTIVE SUMMARY
## TARGET PROFILE  
## DIGITAL FOOTPRINT
## KEY FINDINGS (ranked by significance, with confidence levels)
## RISK ASSESSMENT
## CONNECTIONS & CORRELATIONS
## INTELLIGENCE GAPS
## RECOMMENDED ACTIONS

Every claim must be supported by the data. Be concise but thorough."""

        cache_key = f"report_{hashlib.md5(data_str[:500].encode()).hexdigest()}"
        result = self._query(prompt, cache_key)
        if result:
            self._log("AI intelligence report generated", 'success')
        return result
