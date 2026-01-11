#!/usr/bin/env python3
"""
A1OSINT - The Ultimate OSINT Intelligence Entity
Professional-grade autonomous intelligence gathering with built-in data libraries.
"""

import argparse
import sys
import json
import socket
import requests
import re
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import quote, urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pathlib import Path
import hashlib
from collections import deque

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.keys import Keys
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.firefox import GeckoDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_banner():
    banner = f"""{Colors.OKCYAN}
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║  █████╗  ██╗ ██████╗ ███████╗██╗███╗   ██╗████████║
    ║ ██╔══██╗███║██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝║
    ║ ███████║╚██║██║   ██║███████╗██║██╔██╗ ██║   ██║   ║ 
    ║ ██╔══██║ ██║██║   ██║╚════██║██║██║╚██╗██║   ██║   ║ 
    ║ ██║  ██║ ██║╚██████╔╝███████║██║██║ ╚████║   ██║   ║ 
    ║ ╚═╝  ╚═╝ ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ║ 
    ║                                                    ║
    ║        Professional Intelligence Platform          ║
    ║           A1OSINT - Hunter & Librarian             ║
    ╚════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.DIM}    Autonomous Intelligence • Data Libraries • Deep Analysis{Colors.ENDC}
    """
    print(banner)

class IntelLibrary:
    """Built-in intelligence libraries for instant lookups"""
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.breach_db = self._load_breach_database()
        self.known_ips = self._load_ip_database()
        self.disposable_domains = self._load_disposable_domains()

    def _load_breach_database(self):
        """Load known breach database"""
        try:
            if Path('breach_library.json').exists():
                with open('breach_library.json', 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _load_ip_database(self):
        """Load known malicious IP database"""
        try:
            if Path('ip_library.json').exists():
                with open('ip_library.json', 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _load_disposable_domains(self):
        """Load disposable email domains"""
        return set([
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'maildrop.cc', 'mailinator.com',
            'temp-mail.org', 'getnada.com', 'trashmail.com',
            'sharklasers.com', 'guerrillamail.info', 'grr.la',
            'guerrillamail.biz', 'guerrillamail.de', 'spam4.me',
            'mintemail.com', 'yopmail.com', 'fakeinbox.com'
        ])

    def check_email_breach(self, email):
        """Check if email is in known breach database"""
        return self.breach_db.get(email.lower(), None)

    def check_ip_reputation(self, ip):
        """Check IP reputation in local database"""
        return self.known_ips.get(ip, None)

    def is_disposable_email(self, domain):
        """Check if email domain is disposable"""
        return domain.lower() in self.disposable_domains

class RelevanceFilter:
    """Intelligent relevance filtering system"""
    # Noise patterns to ignore
    NOISE_DOMAINS = {
        'google.com', 'gstatic.com', 'googleapis.com', 'google-analytics.com',
        'facebook.com', 'fbcdn.net', 'facebook.net',
        'doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com',
        'googletagmanager.com', 'recaptcha.net', 'cloudflare.com',
        'jquery.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
        'bootstrapcdn.com', 'fontawesome.com', 'fonts.googleapis.com'
    }

    NOISE_USERNAMES = {
        'font', 'css', 'style', 'license', 'about', 'contact', 'admin',
        'info', 'support', 'help', 'test', 'user', 'demo', 'example',
        'privacy', 'terms', 'login', 'register', 'api'
    }

    @staticmethod
    def is_relevant_domain(domain):
        """Check if domain is relevant for investigation"""
        domain_lower = domain.lower()
        # Filter noise domains
        for noise in RelevanceFilter.NOISE_DOMAINS:
            if noise in domain_lower:
                return False
        # Filter wildcards and malformed
        if '*' in domain or domain.startswith('.') or not '.' in domain:
            return False
        return True

    @staticmethod
    def is_relevant_username(username):
        """Check if username is worth investigating"""
        username_lower = username.lower()
        # Filter noise usernames
        if username_lower in RelevanceFilter.NOISE_USERNAMES:
            return False
        # Filter too short or too long
        if len(username) < 3 or len(username) > 30:
            return False
        # Filter if all numbers
        if username.isdigit():
            return False
        return True

    @staticmethod
    def is_relevant_email(email):
        """Check if email is worth investigating"""
        try:
            local, domain = email.split('@')
            # Filter generic emails
            generic = ['noreply', 'no-reply', 'info', 'admin', 'support', 'hello']
            if any(g in local.lower() for g in generic):
                return False
            return True
        except:
            return False

    @staticmethod
    def calculate_confidence(entity_type, entity_value, context):
        """Calculate confidence score based on context"""
        confidence = 0.5  # Base confidence
        if entity_type == 'email':
            # Higher confidence if domain matches target
            if context.get('target_domain') and context['target_domain'] in entity_value:
                confidence += 0.4
            # Higher confidence if found in profile (not generic page)
            if context.get('source_type') == 'profile':
                confidence += 0.2
            # Lower if disposable
            domain = entity_value.split('@')[1]
            if not RelevanceFilter.is_relevant_email(entity_value):
                confidence -= 0.3
        elif entity_type == 'username':
            if not RelevanceFilter.is_relevant_username(entity_value):
                return 0.1  # Very low confidence for noise
            # Higher confidence if verified on platform
            if context.get('verified'):
                confidence += 0.4
            # Higher if from bio/description
            if context.get('from_bio'):
                confidence += 0.2
        elif entity_type == 'domain':
            if not RelevanceFilter.is_relevant_domain(entity_value):
                return 0.1
            # Higher if from personal website link
            if context.get('is_personal_site'):
                confidence += 0.3
        elif entity_type == 'person':
            # Higher if from verified profile
            if context.get('verified_profile'):
                confidence += 0.4
        return min(confidence, 1.0)  # Cap at 1.0

class IntelligenceStore:
    """Central intelligence storage with relevance filtering"""
    def __init__(self, verbose=False):
        self.nodes = {}
        self.queue = deque()
        self.verbose = verbose
        self.connections = []
        self.discovery_timeline = []
        self.processed_count = 0
        self.skipped_count = 0

    def log(self, message, level='info'):
        if not self.verbose:
            return
        colors = {
            'info': Colors.OKBLUE,
            'success': Colors.OKGREEN,
            'warning': Colors.WARNING,
            'error': Colors.FAIL,
            'hunt': Colors.OKCYAN,
            'skip': Colors.DIM
        }
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {colors.get(level, '')}{message}{Colors.ENDC}")

    def add_node(self, node_type, node_value, source="initial", depth=0, confidence=0.5, context=None):
        if not node_value or not node_type:
            return
        # Calculate real confidence
        if context:
            confidence = RelevanceFilter.calculate_confidence(node_type, node_value, context)
        # Skip low confidence nodes
        if confidence < 0.3:
            self.skipped_count += 1
            self.log(f"SKIPPED: {node_type} '{node_value}' (confidence too low: {confidence:.0%})", 'skip')
            return
        node_type = node_type.strip().lower()
        node_value = str(node_value).strip()
        key = f"{node_type}:{node_value.lower()}"
        if key in self.nodes:
            # Update confidence if higher
            if confidence > self.nodes[key]['confidence']:
                self.nodes[key]['confidence'] = confidence
            if source not in self.nodes[key]['sources']:
                self.nodes[key]['sources'].append(source)
            return
        self.log(f"TARGET: {node_type.upper()} '{node_value}' [{confidence:.0%}]", 'hunt')
        self.nodes[key] = {
            'type': node_type,
            'value': node_value,
            'status': 'queued',
            'depth': depth,
            'sources': [source],
            'results': {},
            'confidence': confidence,
            'discovered_at': datetime.now().isoformat()
        }
        self.queue.append(key)
        self.discovery_timeline.append({
            'time': datetime.now().isoformat(),
            'node': key,
            'source': source,
            'confidence': confidence
        })

    def add_connection(self, source_key, target_key, relationship):
        """Track relationships between entities"""
        self.connections.append({
            'from': source_key,
            'to': target_key,
            'type': relationship,
            'discovered_at': datetime.now().isoformat()
        })

    def get_next_job(self):
        # Sort queue by confidence (process high-confidence targets first)
        if not self.queue:
            return None
        # Get highest confidence job
        best_job = None
        best_confidence = 0
        for key in list(self.queue):
            if self.nodes[key]['status'] != 'queued':
                self.queue.remove(key)
                continue
            if self.nodes[key]['confidence'] > best_confidence:
                best_confidence = self.nodes[key]['confidence']
                best_job = key
        if best_job:
            self.queue.remove(best_job)
            self.nodes[best_job]['status'] = 'processing'
            return self.nodes[best_job]
        return None

    def mark_processed(self, key, results):
        key_lower = key.lower()
        if key_lower in self.nodes:
            self.nodes[key_lower]['status'] = 'processed'
            self.nodes[key_lower]['results'] = results
            self.nodes[key_lower]['completed_at'] = datetime.now().isoformat()
            self.processed_count += 1

    def get_statistics(self):
        return {
            'total_discovered': len(self.nodes),
            'processed': self.processed_count,
            'skipped_low_confidence': self.skipped_count,
            'high_confidence_targets': len([n for n in self.nodes.values() if n['confidence'] > 0.7]),
            'nodes_by_type': self._count_by_type(),
            'connections': len(self.connections)
        }

    def _count_by_type(self):
        counts = {}
        for node in self.nodes.values():
            if node['status'] == 'processed':
                ntype = node['type']
                counts[ntype] = counts.get(ntype, 0) + 1
        return counts

    def get_high_value_nodes(self):
        """Get only high-confidence, processed nodes"""
        return {k: v for k, v in self.nodes.items() 
                if v['status'] == 'processed' and v['confidence'] >= 0.5 and v['results']}

class DeepProfileHunter:
    """Specialized deep profile analyzer"""
    def __init__(self, driver, verbose=False):
        self.driver = driver
        self.verbose = verbose

    def log(self, message, level='info'):
        if not self.verbose:
            return
        colors = {'info': Colors.OKBLUE, 'success': Colors.OKGREEN, 'warning': Colors.WARNING, 'error': Colors.FAIL}
        print(f"    {colors.get(level, '')}[HUNTER] {message}{Colors.ENDC}")

    def hunt_github(self, username):
        """Deep GitHub analysis"""
        self.log(f"Hunting GitHub: @{username}", 'info')
        data = {'profile': {}, 'repositories': [], 'activity': []}
        try:
            url = f"https://github.com/{username}"
            self.driver.get(url)
            time.sleep(2)
            # Profile extraction
            try:
                name_el = self.driver.find_element(By.CSS_SELECTOR, 'span[itemprop="name"]')
                data['profile']['name'] = name_el.text.strip()
            except: pass
            try:
                bio_el = self.driver.find_element(By.CSS_SELECTOR, 'div[data-bio-text]')
                data['profile']['bio'] = bio_el.text.strip()
            except: pass
            try:
                location_el = self.driver.find_element(By.CSS_SELECTOR, 'span[itemprop="homeLocation"]')
                data['profile']['location'] = location_el.text.strip()
            except: pass
            try:
                website_el = self.driver.find_element(By.CSS_SELECTOR, 'a[rel="nofollow me"]')
                data['profile']['website'] = website_el.get_attribute('href')
            except: pass
            try:
                email_el = self.driver.find_element(By.CSS_SELECTOR, 'a[href^="mailto:"]')
                data['profile']['email'] = email_el.get_attribute('href').replace('mailto:', '')
            except: pass
            # Followers/Following
            try:
                followers_el = self.driver.find_element(By.XPATH, "//a[contains( @href, 'followers')]/span")
                data['profile']['followers'] = followers_el.text.strip()
            except: pass
            try:
                following_el = self.driver.find_element(By.XPATH, "//a[contains( @href, 'following')]/span")
                data['profile']['following'] = following_el.text.strip()
            except: pass
            # Top repositories
            try:
                self.driver.get(f"https://github.com/{username}?tab=repositories")
                time.sleep(2)
                repo_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[id^="user-repositories-list"] h3 a')[:10]
                for repo in repo_elements:
                    data['repositories'].append({
                        'name': repo.text.strip(),
                        'url': repo.get_attribute('href')
                    })
            except: pass
            self.log(f"GitHub complete: {len(data['repositories'])} repos", 'success')
        except Exception as e:
            self.log(f"GitHub failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_reddit(self, username):
        """Deep Reddit profile analysis"""
        self.log(f"Hunting Reddit: u/{username}", 'info')
        data = {'profile': {}, 'posts': [], 'comments': [], 'subreddits': set()}
        try:
            url = f"https://www.reddit.com/user/{username}"
            self.driver.get(url)
            time.sleep(3)
            # Profile stats
            try:
                karma_el = self.driver.find_element(By.CSS_SELECTOR, '#profile--id-card--highlight-tooltip--karma')
                data['profile']['karma'] = karma_el.text.strip()
            except: pass
            try:
                cake_day_el = self.driver.find_element(By.CSS_SELECTOR, '#profile--id-card--highlight-tooltip--cakeday')
                data['profile']['cake_day'] = cake_day_el.text.strip()
            except: pass
            # Recent posts
            try:
                post_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-testid="post-container"] ')[:15]
                for post in post_elements:
                    try:
                        title = post.find_element(By.CSS_SELECTOR, 'h3').text.strip()
                        subreddit = post.find_element(By.CSS_SELECTOR, 'a[data-click-id="subreddit"]').text.strip()
                        try:
                            content = post.find_element(By.CSS_SELECTOR, 'div[data-click-id="text"]').text.strip()
                        except:
                            content = None
                        data['posts'].append({
                            'title': title,
                            'subreddit': subreddit,
                            'content': content[:300] if content else None
                        })
                        data['subreddits'].add(subreddit)
                    except: pass
            except: pass
            # Comments
            try:
                self.driver.get(f"https://www.reddit.com/user/{username}/comments")
                time.sleep(2)
                comment_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-testid="comment"]')[:15]
                for comment in comment_elements:
                    try:
                        text = comment.text.strip()[:300]
                        data['comments'].append({'text': text})
                    except: pass
            except: pass
            data['subreddits'] = list(data['subreddits'])
            self.log(f"Reddit complete: {len(data['posts'])} posts, {len(data['comments'])} comments", 'success')
        except Exception as e:
            self.log(f"Reddit failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_instagram(self, username):
        """Deep Instagram profile analysis"""
        self.log(f"Hunting Instagram: @{username}", 'info')
        data = {'profile': {}, 'posts': []}
        try:
            url = f"https://www.instagram.com/{username}/"
            self.driver.get(url)
            time.sleep(4)
            # Scroll to load content
            self.driver.execute_script("window.scrollTo(0, 500);")
            time.sleep(1)
            # Extract from page source
            page_source = self.driver.page_source
            # Try to extract bio
            try:
                bio_match = re.search(r'"biography":"([^"]+)"', page_source)
                if bio_match:
                    bio = bio_match.group(1).encode().decode('unicode_escape')
                    data['profile']['bio'] = bio
            except: pass
            # Basic stats
            try:
                posts_el = self.driver.find_element(By.XPATH, "//span[contains(text(), 'posts')]//preceding-sibling::span")
                data['profile']['posts_count'] = posts_el.text.strip()
            except: pass
            try:
                followers_el = self.driver.find_element(By.XPATH, "//a[contains( @href, '/followers/')]//span")
                data['profile']['followers'] = followers_el.text.strip()
            except: pass
            try:
                following_el = self.driver.find_element(By.XPATH, "//a[contains( @href, '/following')]/span")
                data['profile']['following'] = following_el.text.strip()
            except: pass
            # Post links
            try:
                post_links = self.driver.find_elements(By.CSS_SELECTOR, 'article a[href*="/p/"] ')[:9]
                for link in post_links:
                    try:
                        post_url = link.get_attribute('href')
                        try:
                            img = link.find_element(By.TAG_NAME, 'img')
                            alt_text = img.get_attribute('alt')
                            data['posts'].append({
                                'url': post_url,
                                'caption': alt_text[:200] if alt_text else None
                            })
                        except: 
                            data['posts'].append({'url': post_url})
                    except: 
                        continue
            except: pass
            self.log(f"Instagram complete: {len(data['posts'])} posts", 'success')
        except Exception as e:
            self.log(f"Instagram failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_medium(self, username):
        """Deep Medium profile analysis"""
        self.log(f"Hunting Medium: @{username}", 'info')
        data = {'profile': {}, 'articles': []}
        try:
            url = f"https://medium.com/@{username}"
            self.driver.get(url)
            time.sleep(3)
            # Profile info
            try:
                name_el = self.driver.find_element(By.CSS_SELECTOR, 'h2')
                data['profile']['name'] = name_el.text.strip()
            except: pass
            try:
                bio_el = self.driver.find_element(By.CSS_SELECTOR, 'p[class*="bio"]')
                data['profile']['bio'] = bio_el.text.strip()
            except: pass
            # Articles
            try:
                article_elements = self.driver.find_elements(By.CSS_SELECTOR, 'article')[:10]
                for article in article_elements:
                    try:
                        title = article.find_element(By.CSS_SELECTOR, 'h2, h3').text.strip()
                        try:
                            preview = article.find_element(By.CSS_SELECTOR, 'p').text.strip()
                        except: 
                            preview = None
                        try:
                            link = article.find_element(By.TAG_NAME, 'a').get_attribute('href')
                        except: 
                            link = None
                        data['articles'].append({
                            'title': title,
                            'preview': preview[:200] if preview else None,
                            'url': link
                        })
                    except: pass
            except: pass
            self.log(f"Medium complete: {len(data['articles'])} articles", 'success')
        except Exception as e:
            self.log(f"Medium failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_youtube(self, channel_id):
        """Deep YouTube channel analysis"""
        self.log(f"Hunting YouTube channel", 'info')
        data = {'channel': {}, 'videos': [], 'about': {}}
        try:
            url = f"https://www.youtube.com/@{channel_id}" if not channel_id.startswith('UC') else f"https://www.youtube.com/channel/{channel_id}"
            self.driver.get(url)
            time.sleep(3)
            # Subscriber count
            try:
                subscriber_el = self.driver.find_element(By.CSS_SELECTOR, '#subscriber-count')
                data['channel']['subscribers'] = subscriber_el.text.strip()
            except: pass
            # About section
            try:
                self.driver.get(url + '/about')
                time.sleep(2)
                description_el = self.driver.find_element(By.CSS_SELECTOR, '#description')
                data['about']['description'] = description_el.text.strip()
                try:
                    email_el = self.driver.find_element(By.CSS_SELECTOR, 'a[href^="mailto:"]')
                    data['about']['email'] = email_el.get_attribute('href').replace('mailto:', '')
                except: pass
                try:
                    link_elements = self.driver.find_elements(By.CSS_SELECTOR, 'a[class*="channel-header-links"]')
                    data['about']['links'] = [link.get_attribute('href') for link in link_elements]
                except: pass
            except: pass
            # Recent videos
            try:
                self.driver.get(url + '/videos')
                time.sleep(2)
                video_elements = self.driver.find_elements(By.CSS_SELECTOR, 'ytd-grid-video-renderer')[:10]
                for video in video_elements:
                    try:
                        title = video.find_element(By.CSS_SELECTOR, '#video-title').text.strip()
                        video_url = video.find_element(By.CSS_SELECTOR, '#video-title').get_attribute('href')
                        try:
                            metadata = video.find_element(By.CSS_SELECTOR, '#metadata-line').text.strip()
                        except: 
                            metadata = None
                        data['videos'].append({
                            'title': title,
                            'url': video_url,
                            'metadata': metadata
                        })
                    except: pass
            except: pass
            self.log(f"YouTube complete: {len(data['videos'])} videos", 'success')
        except Exception as e:
            self.log(f"YouTube failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_twitch(self, username):
        """Deep Twitch profile analysis"""
        self.log(f"Hunting Twitch: {username}", 'info')
        data = {'profile': {}, 'videos': []}
        try:
            url = f"https://www.twitch.tv/{username}"
            self.driver.get(url)
            time.sleep(4)
            # Profile description
            try:
                desc_el = self.driver.find_element(By.CSS_SELECTOR, 'p[class*="about-section"]')
                data['profile']['description'] = desc_el.text.strip()
            except: pass
            # Follower count
            try:
                follower_el = self.driver.find_element(By.CSS_SELECTOR, 'div[class*="followers"]')
                data['profile']['followers'] = follower_el.text.strip()
            except: pass
            # Recent videos
            try:
                self.driver.get(f"https://www.twitch.tv/{username}/videos")
                time.sleep(2)
                video_elements = self.driver.find_elements(By.CSS_SELECTOR, 'article')[:10]
                for video in video_elements:
                    try:
                        title = video.find_element(By.CSS_SELECTOR, 'a[class*="title"]').text.strip()
                        video_url = video.find_element(By.CSS_SELECTOR, 'a').get_attribute('href')
                        data['videos'].append({
                            'title': title,
                            'url': video_url
                        })
                    except: pass
            except: pass
            self.log(f"Twitch complete: {len(data['videos'])} videos", 'success')
        except Exception as e:
            self.log(f"Twitch failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_tiktok(self, username):
        """Deep TikTok profile analysis"""
        self.log(f"Hunting TikTok: @{username}", 'info')
        data = {'profile': {}, 'videos': []}
        try:
            url = f"https://www.tiktok.com/@{username}"
            self.driver.get(url)
            time.sleep(4)
            # Scroll to load videos
            self.driver.execute_script("window.scrollTo(0, 800);")
            time.sleep(2)
            # Profile stats
            try:
                stats = self.driver.find_elements(By.CSS_SELECTOR, 'strong[data-e2e="followers-count"], strong[data-e2e="following-count"]')
                if len(stats) >= 2:
                    data['profile']['followers'] = stats[0].text.strip()
                    data['profile']['following'] = stats[1].text.strip()
            except: pass
            # Bio
            try:
                bio_el = self.driver.find_element(By.CSS_SELECTOR, 'h2[data-e2e="user-bio"]')
                data['profile']['bio'] = bio_el.text.strip()
            except: pass
            # Videos
            try:
                video_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-e2e="user-post-item"]')[:12]
                for video in video_elements:
                    try:
                        desc = video.find_element(By.CSS_SELECTOR, 'img').get_attribute('alt')
                        video_link = video.find_element(By.TAG_NAME, 'a').get_attribute('href')
                        data['videos'].append({
                            'url': video_link,
                            'description': desc[:150] if desc else None
                        })
                    except: pass
            except: pass
            self.log(f"TikTok complete: {len(data['videos'])} videos", 'success')
        except Exception as e:
            self.log(f"TikTok failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_facebook(self, username):
        """Deep Facebook profile analysis"""
        self.log(f"Hunting Facebook: {username}", 'info')
        data = {'profile': {}, 'posts': []}
        try:
            url = f"https://www.facebook.com/{username}"
            self.driver.get(url)
            time.sleep(3)
            # Try to extract visible content
            try:
                bio_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[dir="auto"]')
                for element in bio_elements[:5]:
                    text = element.text.strip()
                    if len(text) > 20:
                        data['profile']['bio'] = text[:300]
                        break
            except: pass
            # Recent posts
            try:
                post_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-ad-preview="message"]')[:5]
                for post in post_elements:
                    try:
                        post_text = post.text.strip()
                        if post_text:
                            data['posts'].append({'content': post_text[:300]})
                    except: pass
            except: pass
            self.log(f"Facebook complete: {len(data['posts'])} posts", 'success')
        except Exception as e:
            self.log(f"Facebook failed: {e}", 'error')
            data['error'] = str(e)
        return data

    def hunt_linkedin(self, profile_url):
        """Deep LinkedIn analysis"""
        self.log(f"Hunting LinkedIn profile", 'info')
        data = {'profile': {}, 'experience': [], 'education': []}
        try:
            self.driver.get(profile_url)
            time.sleep(3)
            try:
                name_el = self.driver.find_element(By.CSS_SELECTOR, 'h1.top-card-layout__title')
                data['profile']['name'] = name_el.text.strip()
            except: pass
            try:
                headline_el = self.driver.find_element(By.CSS_SELECTOR, 'h2.top-card-layout__headline')
                data['profile']['headline'] = headline_el.text.strip()
            except: pass
            try:
                location_el = self.driver.find_element(By.CSS_SELECTOR, 'div.top-card__subline-item')
                data['profile']['location'] = location_el.text.strip()
            except: pass
            # Experience
            try:
                exp_elements = self.driver.find_elements(By.CSS_SELECTOR, 'section[data-section="experience"] li')[:5]
                for exp in exp_elements:
                    try:
                        title = exp.find_element(By.CSS_SELECTOR, 'h3').text.strip()
                        company = exp.find_element(By.CSS_SELECTOR, 'h4').text.strip()
                        data['experience'].append({'title': title, 'company': company})
                    except: pass
            except: pass
            self.log(f"LinkedIn complete: {len(data['experience'])} jobs", 'success')
        except Exception as e:
            self.log(f"LinkedIn failed: {e}", 'error')
            data['error'] = str(e)
        return data

class A1OSINT: # Renamed from ULTIMA to A1OSINT
    """The professional intelligence entity"""
    def __init__(self, verbose=False, max_depth=2, proxy=None, browser='chrome'):
        self.verbose = verbose
        self.max_depth = max_depth
        self.proxy = proxy
        self.browser_type = browser
        self.store = IntelligenceStore(verbose)
        self.library = IntelLibrary(verbose)
        self.driver = None
        self.hunter = None
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        # Load platforms
        self.sites = self._load_sites()
        # Entity patterns
        self.patterns = {
            'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'phone': re.compile(r'[+]?[(]?[0-9]{1,4}[)]?[-\s.]?[(]?[0-9]{1,4}[)]?[-\s.]?[0-9]{1,4}[-\s.]?[0-9]{1,9}'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'username': re.compile(r'@([a-zA-Z0-9_]{3,15})\b')
        }
    
    def _load_sites(self):
        try:
            with open('sites.json', 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def log(self, message, level='info'):
        if not self.verbose:
            return
        colors = {'info': Colors.OKBLUE, 'success': Colors.OKGREEN, 'warning': Colors.WARNING, 'error': Colors.FAIL}
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {colors.get(level, '')}[A1OSINT] {message}{Colors.ENDC}")
    
    def _init_browser(self):
        if not SELENIUM_AVAILABLE or self.driver:
            return
        self.log(f"Initializing browser for deep analysis...", 'info')
        try:
            if self.browser_type == 'chrome':
                options = webdriver.ChromeOptions()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                if self.proxy:
                    options.add_argument(f'--proxy-server={self.proxy}')
                service = ChromeService(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=options)
            else:
                options = webdriver.FirefoxOptions()
                options.add_argument('--headless')
                service = FirefoxService(GeckoDriverManager().install())
                self.driver = webdriver.Firefox(service=service, options=options)
            
            self.driver.set_page_load_timeout(20)
            self.hunter = DeepProfileHunter(self.driver, self.verbose)
            self.log("Browser ready", 'success')
        except Exception as e:
            self.log(f"Browser init failed: {e}", 'error')
    
    def _quit_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def extract_entities(self, text, context=None):
        """Extract relevant entities from text"""
        entities = []
        # Emails
        for email in self.patterns['email'].finditer(text):
            email_addr = email.group(0)
            if RelevanceFilter.is_relevant_email(email_addr):
                entities.append(('email', email_addr, context or {}))
        # URLs - extract domains only
        for url in self.patterns['url'].finditer(text):
            url_str = url.group(0)
            try:
                domain = urlparse(url_str).netloc
                if domain and RelevanceFilter.is_relevant_domain(domain):
                    entities.append(('domain', domain, context or {}))
            except:
                pass
        # Usernames from @ mentions
        for username in self.patterns['username'].finditer(text):
            user = username.group(1)
            if RelevanceFilter.is_relevant_username(user):
                entities.append(('username', user, context or {}))
        return entities
    
    def hunt_username(self, job):
        """Hunt username across platforms"""
        username = job['value']
        self.log(f"Hunting username: {username}", 'info')
        
        results = {'platforms_found': []}
        new_nodes = []
        
        def check_site(platform, config):
            try:
                url = config['url'].format(username)
                r = self.session.get(url, timeout=5, allow_redirects=True)
                
                error_type = config.get('errorType', 'status_code')
                found = False
                
                if error_type == 'status_code':
                    found = r.status_code == 200
                elif error_type == 'message':
                    error_msg = config.get('errorMsg', '')
                    found = r.status_code == 200 and error_msg.lower() not in r.text.lower()
                
                if found:
                    return {'platform': platform, 'url': url}
            except:
                pass
            return None
        
        if self.sites:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_site, name, config): name for name, config in self.sites.items()}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['platforms_found'].append(result)
                        new_nodes.append({
                            'type': 'profile_url',
                            'value': result['url'],
                            'platform': result['platform'],
                            'context': {'verified': True, 'source_type': 'profile'}
                        })
        else:
             self.log("sites.json missing or empty. Skipping platform checks.", 'warning')

        return results, new_nodes
    
    def hunt_profile_url(self, job):
        """Deep profile analysis"""
        url = job['value']
        platform = job.get('platform', 'unknown')
        self.log(f"Deep analysis: {platform}", 'info')
        results = {}
        new_nodes = []
        if not self.hunter:
            return results, new_nodes
        try:
            username = url.rstrip('/').split('/')[-1].replace('@', '')
            context = {'source_type': 'profile', 'verified': True}
            
            if 'github.com' in url:
                data = self.hunter.hunt_github(username)
                results['github'] = data
                # Extract high-value entities
                if data.get('profile', {}).get('email'):
                    new_nodes.append({
                        'type': 'email',
                        'value': data['profile']['email'],
                        'context': {**context, 'from_bio': True, 'is_personal': True}
                    })
                if data.get('profile', {}).get('name'):
                    new_nodes.append({
                        'type': 'person',
                        'value': data['profile']['name'],
                        'context': {**context, 'verified_profile': True}
                    })
                if data.get('profile', {}).get('website'):
                    new_nodes.append({
                        'type': 'url',
                        'value': data['profile']['website'],
                        'context': {**context, 'is_personal_site': True}
                    })
                # Extract from bio
                bio = data.get('profile', {}).get('bio', '')
                for etype, evalue, _ in self.extract_entities(bio, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Website
                website = data.get('profile', {}).get('website', '')
                if website:
                    new_nodes.append({'type': 'url', 'value': website, 'context': {**context, 'is_personal_site': True}})
            elif 'linkedin.com' in url:
                data = self.hunter.hunt_linkedin(url)
                results['linkedin'] = data
                if data.get('profile', {}).get('name'):
                    new_nodes.append({
                        'type': 'person',
                        'value': data['profile']['name'],
                        'context': {**context, 'verified_profile': True}
                    })
                # Extract from headline
                headline = data.get('profile', {}).get('headline', '')
                for etype, evalue, _ in self.extract_entities(headline, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Companies from experience
                for exp in data.get('experience', []):
                    if exp.get('company'):
                        new_nodes.append({
                            'type': 'company',
                            'value': exp['company'],
                            'context': {**context, 'employment': True}
                        })
            elif 'reddit.com' in url:
                data = self.hunter.hunt_reddit(username)
                results['reddit'] = data
                # Extract from posts
                for post in data.get('posts', []):
                    for etype, evalue, _ in self.extract_entities(post.get('title', ''), context):
                        new_nodes.append({'type': etype, 'value': evalue, 'context': context})
                    if post.get('content'):
                        for etype, evalue, _ in self.extract_entities(post['content'], context):
                            new_nodes.append({'type': etype, 'value': evalue, 'context': context})
                # Extract from comments
                for comment in data.get('comments', [])[:5]:
                    for etype, evalue, _ in self.extract_entities(comment.get('text', ''), context):
                        new_nodes.append({'type': etype, 'value': evalue, 'context': context})
            elif 'instagram.com' in url:
                data = self.hunter.hunt_instagram(username)
                results['instagram'] = data
                # Extract from bio
                bio = data.get('profile', {}).get('bio', '')
                for etype, evalue, _ in self.extract_entities(bio, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Extract from post captions
                for post in data.get('posts', []):
                    caption = post.get('caption', '')
                    if caption:
                        for etype, evalue, _ in self.extract_entities(caption, context):
                            new_nodes.append({'type': etype, 'value': evalue, 'context': context})
            elif 'facebook.com' in url:
                data = self.hunter.hunt_facebook(username)
                results['facebook'] = data
                # Extract from bio
                bio = data.get('profile', {}).get('bio', '')
                for etype, evalue, _ in self.extract_entities(bio, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Extract from posts
                for post in data.get('posts', []):
                    for etype, evalue, _ in self.extract_entities(post.get('content', ''), context):
                        new_nodes.append({'type': etype, 'value': evalue, 'context': context})
            elif 'tiktok.com' in url:
                data = self.hunter.hunt_tiktok(username)
                results['tiktok'] = data
                # Extract from bio
                bio = data.get('profile', {}).get('bio', '')
                for etype, evalue, _ in self.extract_entities(bio, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Extract from video descriptions
                for video in data.get('videos', []):
                    desc = video.get('description', '')
                    if desc:
                        for etype, evalue, _ in self.extract_entities(desc, context):
                            new_nodes.append({'type': etype, 'value': evalue, 'context': context})
            elif 'medium.com' in url:
                data = self.hunter.hunt_medium(username)
                results['medium'] = data
                # Extract from bio
                bio = data.get('profile', {}).get('bio', '')
                for etype, evalue, _ in self.extract_entities(bio, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                if data.get('profile', {}).get('name'):
                    new_nodes.append({
                        'type': 'person',
                        'value': data['profile']['name'],
                        'context': {**context, 'verified_profile': True}
                    })
                # Extract from article previews
                for article in data.get('articles', [])[:5]:
                    preview = article.get('preview', '')
                    if preview:
                        for etype, evalue, _ in self.extract_entities(preview, context):
                            new_nodes.append({'type': etype, 'value': evalue, 'context': context})
            elif 'youtube.com' in url or 'youtu.be' in url:
                channel_id = username
                data = self.hunter.hunt_youtube(channel_id)
                results['youtube'] = data
                # Extract from description
                desc = data.get('about', {}).get('description', '')
                for etype, evalue, _ in self.extract_entities(desc, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
                # Extract email if available
                if data.get('about', {}).get('email'):
                    new_nodes.append({
                        'type': 'email',
                        'value': data['about']['email'],
                        'context': {**context, 'is_personal': True}
                    })
                # Extract from social links
                for link in data.get('about', {}).get('links', []):
                    new_nodes.append({
                        'type': 'url',
                        'value': link,
                        'context': {**context, 'social_link': True}
                    })
            elif 'twitch.tv' in url:
                data = self.hunter.hunt_twitch(username)
                results['twitch'] = data
                # Extract from description
                desc = data.get('profile', {}).get('description', '')
                for etype, evalue, _ in self.extract_entities(desc, {**context, 'from_bio': True}):
                    new_nodes.append({'type': etype, 'value': evalue, 'context': {**context, 'from_bio': True}})
            else:
                # Generic scraping for unknown platforms
                self.log(f"Generic scrape for {platform}", 'info')
                try:
                    self.driver.get(url)
                    time.sleep(3)
                    page_text = self.driver.page_source[:30000]  # Limit text size
                    # Extract entities
                    for etype, evalue, _ in self.extract_entities(page_text, context):
                        new_nodes.append({'type': etype, 'value': evalue, 'context': context})
                    if new_nodes:
                        results['generic_scrape'] = {
                            'entities_extracted': len(new_nodes)
                        }
                except Exception as e:
                    self.log(f"Generic scrape failed: {e}", 'error')
        except Exception as e:
            self.log(f"Deep analysis failed: {e}", 'error')
            results['error'] = str(e)
        return results, new_nodes
    
    def hunt_email(self, job):
        """Email intelligence with library lookup"""
        email = job['value']
        self.log(f"Analyzing email: {email}", 'info')
        results = {'library_check': {}}
        new_nodes = []
        try:
            domain = email.split('@')[1]
            local_part = email.split('@')[0]
            results['domain'] = domain
            results['local_part'] = local_part
            # Library lookup
            breach_data = self.library.check_email_breach(email)
            if breach_data:
                results['library_check']['breaches'] = breach_data
                self.log(f"BREACH FOUND in library: {email}", 'warning')
            # Check if disposable
            is_disposable = self.library.is_disposable_email(domain)
            results['disposable'] = is_disposable
            if is_disposable:
                self.log(f"Disposable email detected: {domain}", 'warning')
                return results, new_nodes  # Don't pivot on disposable
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results['mx_records'] = [{'host': str(mx.exchange).rstrip('.'), 'priority': mx.preference} for mx in mx_records]
                results['deliverable'] = True
            except:
                results['deliverable'] = False
            # Gravatar
            try:
                email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
                gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
                r = self.session.get(gravatar_url, timeout=3)
                if r.status_code == 200:
                    results['gravatar'] = True
                    profile_url = f"https://gravatar.com/{email_hash}.json"
                    pr = self.session.get(profile_url, timeout=3)
                    if pr.status_code == 200:
                        gdata = pr.json()
                        if 'entry' in gdata and len(gdata['entry']) > 0:
                            entry = gdata['entry'][0]
                            if entry.get('displayName'):
                                new_nodes.append({
                                    'type': 'person',
                                    'value': entry['displayName'],
                                    'context': {**context, 'verified_profile': True, 'source': 'gravatar'}
                                })
            except:
                results['gravatar'] = False
            # Add domain and username for investigation
            new_nodes.append({'type': 'domain', 'value': domain, 'context': {'email_domain': True}})
            new_nodes.append({'type': 'username', 'value': local_part, 'context': {'from_email': True}})
        except Exception as e:
            results['error'] = str(e)
        return results, new_nodes
    
    def hunt_domain(self, job):
        """Domain intelligence"""
        domain = job['value']
        self.log(f"Analyzing domain: {domain}", 'info')
        results = {}
        new_nodes = []
        # DNS
        try:
            ip = socket.gethostbyname(domain)
            results['ip_address'] = ip
            new_nodes.append({'type': 'ip', 'value': ip, 'context': {'domain': domain}})
        except:
            results['error'] = 'Could not resolve domain'
            return results, new_nodes
        # WHOIS
        try:
            w = whois.whois(domain)
            results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None
            }
        except:
            pass
        # Certificate transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = self.session.get(url, timeout=10)
            if r.status_code == 200:
                certs = r.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for subdomain in name.split('\n'):
                        if subdomain.endswith(domain) and '*' not in subdomain:
                            subdomains.add(subdomain.lower())
                results['subdomains'] = list(subdomains)[:20]  # Limit
        except:
            pass
        return results, new_nodes
    
    def hunt_ip(self, job):
        """IP intelligence with library lookup"""
        ip = job['value']
        self.log(f"Analyzing IP: {ip}", 'info')
        results = {'library_check': {}}
        new_nodes = []
        # Library lookup
        reputation = self.library.check_ip_reputation(ip)
        if reputation:
            results['library_check']['reputation'] = reputation
            self.log(f"IP found in library: {reputation}", 'warning')
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)
            results['reverse_dns'] = hostname[0]
            new_nodes.append({'type': 'domain', 'value': hostname[0], 'context': {'reverse_dns': True}})
        except:
            pass
        # Geolocation
        try:
            r = self.session.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if r.status_code == 200:
                geo = r.json()
                results['geolocation'] = {
                    'country': geo.get('country_name'),
                    'city': geo.get('city'),
                    'org': geo.get('org'),
                    'asn': geo.get('asn')
                }
        except:
            pass
        return results, new_nodes
    
    def hunt_person(self, job):
        """Person intelligence"""
        name = job['value']
        self.log(f"Analyzing person: {name}", 'info')
        results = {}
        new_nodes = []
        # Generate username permutations
        parts = re.sub(r'[^a-zA-Z0-9 ]', '', name.lower()).split()
        if parts and len(parts) >= 1:
            permutations = set()
            first = parts[0]
            last = parts[-1] if len(parts) > 1 else parts[0]
            permutations.add(first + last)
            permutations.add(first + '.' + last)
            permutations.add(first + '_' + last)
            if len(first) > 0:
                permutations.add(first[0] + last)
            results['username_variants'] = list(permutations)[:5]
            for username in permutations:
                new_nodes.append({
                    'type': 'username',
                    'value': username,
                    'context': {'generated_from_name': True}
                })
        return results, new_nodes
    
    def start(self, initial_type, initial_value):
        """Start intelligence gathering"""
        self.log(f"INITIATING: {initial_type} = '{initial_value}'", 'info')
        # Initialize browser if needed
        if initial_type in ['username', 'profile_url', 'person']:
            self._init_browser()
        # Add initial target with high confidence
        self.store.add_node(initial_type, initial_value, source='initial', depth=0, confidence=1.0)
        try:
            while True:
                job = self.store.get_next_job()
                if not job:
                    break
                if job['depth'] > self.max_depth:
                    self.store.mark_processed(f"{job['type']}:{job['value']}", {'skipped': 'max_depth'})
                    continue
                # Route to handler
                results = {}
                new_nodes = []
                try:
                    if job['type'] == 'username':
                        results, new_nodes = self.hunt_username(job)
                    elif job['type'] == 'profile_url':
                        results, new_nodes = self.hunt_profile_url(job)
                    elif job['type'] == 'email':
                        results, new_nodes = self.hunt_email(job)
                    elif job['type'] == 'domain':
                        results, new_nodes = self.hunt_domain(job)
                    elif job['type'] == 'ip':
                        results, new_nodes = self.hunt_ip(job)
                    elif job['type'] == 'person':
                        results, new_nodes = self.hunt_person(job)
                    elif job['type'] == 'company':
                        # Add company search logic here
                        results = {'company_name': job['value']}
                except Exception as e:
                    self.log(f"Hunt failed: {e}", 'error')
                    results = {'error': str(e)}
                # Mark processed
                self.store.mark_processed(f"{job['type']}:{job['value']}", results)
                # Add new nodes
                source_key = f"{job['type']}:{job['value']}"
                for node in new_nodes:
                    context = node.get('context', {})
                    self.store.add_node(
                        node['type'],
                        node['value'],
                        source=source_key,
                        depth=job['depth'] + 1,
                        confidence=0.5,
                        context=context
                    )
                    self.store.add_connection(source_key, f"{node['type']}:{node['value']}", 'discovered')
        finally:
            self._quit_browser()
        return self.store.get_high_value_nodes(), self.store.get_statistics()

def format_professional_report(nodes, statistics):
    """Generate professional intelligence report"""
    output = []
    # Header
    output.append(f"{Colors.BOLD}{Colors.HEADER}{'═'*70}{Colors.ENDC}")
    output.append(f"{Colors.BOLD}{Colors.HEADER}{'INTELLIGENCE REPORT':^70}{Colors.ENDC}")
    output.append(f"{Colors.BOLD}{Colors.HEADER}{'═'*70}{Colors.ENDC}\n")
    # Executive Summary
    output.append(f"{Colors.BOLD}EXECUTIVE SUMMARY{Colors.ENDC}")
    output.append(f"{Colors.DIM}{'─'*70}{Colors.ENDC}")
    output.append(f"Total Intelligence Nodes: {statistics['total_discovered']}")
    output.append(f"High-Confidence Targets: {statistics['high_confidence_targets']}")
    output.append(f"Processed Nodes: {statistics['processed']}")
    output.append(f"Low-Confidence Filtered: {statistics['skipped_low_confidence']}")
    output.append(f"Connections Mapped: {statistics['connections']}")
    if statistics['nodes_by_type']:
        output.append(f"\n{Colors.BOLD}Intelligence by Type:{Colors.ENDC}")
        for ntype, count in sorted(statistics['nodes_by_type'].items()):
            output.append(f"  • {ntype.title()}: {count}")
    output.append(f"\n{Colors.BOLD}{'═'*70}{Colors.ENDC}\n")
    # Detailed Findings
    output.append(f"{Colors.BOLD}DETAILED FINDINGS{Colors.ENDC}")
    output.append(f"{Colors.DIM}{'─'*70}{Colors.ENDC}\n")
    # Group by type
    by_type = {}
    for key, node in nodes.items():
        ntype = node['type']
        if ntype not in by_type:
            by_type[ntype] = []
        by_type[ntype].append(node)
    # Display each type
    for ntype in sorted(by_type.keys()):
        nodes_list = by_type[ntype]
        output.append(f"{Colors.OKCYAN}{Colors.BOLD}[{ntype.upper()}] {len(nodes_list)} Found{Colors.ENDC}")
        output.append(f"{Colors.DIM}{'─'*70}{Colors.ENDC}")
        for node in sorted(nodes_list, key=lambda x: x['confidence'], reverse=True):
            confidence_color = Colors.OKGREEN if node['confidence'] > 0.7 else Colors.WARNING if node['confidence'] > 0.5 else Colors.FAIL
            output.append(f"\n  {Colors.BOLD}{node['value']}{Colors.ENDC} {confidence_color}[{node['confidence']:.0%}]{Colors.ENDC}")
            output.append(f"  Source: {', '.join(node['sources'][:2])}")
            results = node.get('results', {})
            if results and 'error' not in results:
                # Email results
                if ntype == 'email':
                    if results.get('library_check', {}).get('breaches'):
                        output.append(f"  {Colors.FAIL}BREACH: Found in data breach database{Colors.ENDC}")
                    if results.get('disposable'):
                        output.append(f"  {Colors.WARNING}Type: Disposable{Colors.ENDC}")
                    else:
                        output.append(f"  Deliverable: {'Yes' if results.get('deliverable') else 'No'}")
                    if results.get('gravatar'):
                        output.append(f"  {Colors.OKGREEN}Gravatar: Profile exists{Colors.ENDC}")
                # Username results
                elif ntype == 'username':
                    platforms = results.get('platforms_found', [])
                    if platforms:
                        output.append(f"  {Colors.OKGREEN}Found on {len(platforms)} platforms:{Colors.ENDC}")
                        for platform in platforms[:5]:
                            output.append(f"    • {platform['platform']}")
                # Profile results
                elif ntype == 'profile_url':
                    # GitHub
                    if 'github' in results:
                        pdata = results['github']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('name'):
                                output.append(f"  Name: {profile['name']}")
                            if profile.get('bio'):
                                bio_preview = profile['bio'][:100] + '...' if len(profile['bio']) > 100 else profile['bio']
                                output.append(f"  Bio: {bio_preview}")
                            if profile.get('location'):
                                output.append(f"  Location: {profile['location']}")
                            if profile.get('email'):
                                output.append(f"  {Colors.OKGREEN}Email: {profile['email']}{Colors.ENDC}")
                            if profile.get('website'):
                                output.append(f"  Website: {profile['website']}")
                            if profile.get('followers'):
                                output.append(f"  Followers: {profile['followers']}")
                        if 'repositories' in pdata and pdata['repositories']:
                            output.append(f"  Repositories: {len(pdata['repositories'])}")
                    # LinkedIn
                    if 'linkedin' in results:
                        pdata = results['linkedin']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('name'):
                                output.append(f"  Name: {profile['name']}")
                            if profile.get('headline'):
                                output.append(f"  Headline: {profile['headline']}")
                            if profile.get('location'):
                                output.append(f"  Location: {profile['location']}")
                        if 'experience' in pdata and pdata['experience']:
                            output.append(f"  Work History: {len(pdata['experience'])} positions")
                            if pdata['experience']:
                                exp = pdata['experience'][0]
                                output.append(f"  Current: {exp.get('title')} at {exp.get('company')}")
                    # Reddit
                    if 'reddit' in results:
                        pdata = results['reddit']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('karma'):
                                output.append(f"  Karma: {profile['karma']}")
                            if profile.get('cake_day'):
                                output.append(f"  Cake Day: {profile['cake_day']}")
                        if 'posts' in pdata and pdata['posts']:
                            output.append(f"  Posts: {len(pdata['posts'])}")
                        if 'comments' in pdata and pdata['comments']:
                            output.append(f"  Comments: {len(pdata['comments'])}")
                        if 'subreddits' in pdata and pdata['subreddits']:
                            output.append(f"  Active in: {', '.join(pdata['subreddits'][:5])}")
                    # Instagram
                    if 'instagram' in results:
                        pdata = results['instagram']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('bio'):
                                output.append(f"  Bio: {profile['bio'][:80]}...")
                            if profile.get('followers'):
                                output.append(f"  Followers: {profile['followers']}")
                            if profile.get('posts_count'):
                                output.append(f"  Posts: {profile['posts_count']}")
                        if 'posts' in pdata and pdata['posts']:
                            output.append(f"  Recent Posts: {len(pdata['posts'])} analyzed")
                    # TikTok
                    if 'tiktok' in results:
                        pdata = results['tiktok']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('bio'):
                                output.append(f"  Bio: {profile['bio'][:80]}...")
                            if profile.get('followers'):
                                output.append(f"  Followers: {profile['followers']}")
                        if 'videos' in pdata and pdata['videos']:
                            output.append(f"  Videos: {len(pdata['videos'])} analyzed")
                    # Medium
                    if 'medium' in results:
                        pdata = results['medium']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('name'):
                                output.append(f"  Name: {profile['name']}")
                            if profile.get('bio'):
                                output.append(f"  Bio: {profile['bio'][:80]}...")
                        if 'articles' in pdata and pdata['articles']:
                            output.append(f"  Articles: {len(pdata['articles'])} published")
                    # YouTube
                    if 'youtube' in results:
                        pdata = results['youtube']
                        if 'channel' in pdata:
                            channel = pdata['channel']
                            if channel.get('subscribers'):
                                output.append(f"  Subscribers: {channel['subscribers']}")
                        if 'about' in pdata:
                            about = pdata['about']
                            if about.get('description'):
                                output.append(f"  Description: {about['description'][:80]}...")
                            if about.get('email'):
                                output.append(f"  {Colors.OKGREEN}Business Email: {about['email']}{Colors.ENDC}")
                        if 'videos' in pdata and pdata['videos']:
                            output.append(f"  Videos: {len(pdata['videos'])} analyzed")
                    # Twitch
                    if 'twitch' in results:
                        pdata = results['twitch']
                        if 'profile' in pdata:
                            profile = pdata['profile']
                            if profile.get('description'):
                                output.append(f"  Description: {profile['description'][:80]}...")
                            if profile.get('followers'):
                                output.append(f"  Followers: {profile['followers']}")
                        if 'videos' in pdata and pdata['videos']:
                            output.append(f"  Videos: {len(pdata['videos'])} analyzed")
                    # Facebook
                    if 'facebook' in results:
                        pdata = results['facebook']
                        if 'profile' in pdata and pdata['profile'].get('bio'):
                            output.append(f"  Bio: {pdata['profile']['bio'][:80]}...")
                        if 'posts' in pdata and pdata['posts']:
                            output.append(f"  Posts: {len(pdata['posts'])} captured")
                # Domain results
                elif ntype == 'domain':
                    if results.get('ip_address'):
                        output.append(f"  IP: {results['ip_address']}")
                    if results.get('whois', {}).get('registrar'):
                        output.append(f"  Registrar: {results['whois']['registrar']}")
                    if results.get('subdomains'):
                        output.append(f"  Subdomains: {len(results['subdomains'])} discovered")
                # IP results
                elif ntype == 'ip':
                    if results.get('library_check', {}).get('reputation'):
                        output.append(f"  {Colors.FAIL}ALERT: {results['library_check']['reputation']}{Colors.ENDC}")
                    if results.get('geolocation'):
                        geo = results['geolocation']
                        output.append(f"  Location: {geo.get('city')}, {geo.get('country')}")
                        output.append(f"  ISP: {geo.get('org')}")
                # Person results
                elif ntype == 'person':
                    if results.get('username_variants'):
                        output.append(f"  Username Variants: {', '.join(results['username_variants'][:3])}")
        output.append("")
    # Footer
    output.append(f"{Colors.BOLD}{Colors.HEADER}{'═'*70}{Colors.ENDC}")
    output.append(f"{Colors.DIM}Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    output.append(f"{Colors.BOLD}{Colors.HEADER}{'═'*70}{Colors.ENDC}\n")
    return '\n'.join(output)

def get_consent(no_consent_flag):
    """
    Prompts the user for consent and returns True if they agree, False otherwise.
    """
    if no_consent_flag:
        return True
    print(f"{Colors.WARNING}LEGAL DISCLAIMER:{Colors.ENDC}")
    print("This tool is intended for legal and ethical purposes only.")
    print("The developer is not responsible for any illegal usage of this tool.")
    print("By using this tool, you agree to use it in a lawful manner and take full responsibility for your actions.")
    while True:
        choice = input("Do you agree to these terms? (yes/no): ").lower().strip()
        if choice in ['yes', 'y']:
            return True
        elif choice in ['no', 'n']:
            return False
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

def main():
    # DEBUG: Inside main(), start
    parser = argparse.ArgumentParser(
        description='A1OSINT - Professional OSINT Intelligence Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Professional-grade intelligence gathering with relevance filtering and data libraries.

Examples:
  python osint.py username johndoe -D 2 -v
  python osint.py email john@example.com -D 2
  python osint.py person "John Doe" -D 3 -v
  python osint.py domain example.com -D 2
  
Features:
  • Intelligent relevance filtering (no noise)
  • Confidence scoring for all findings
  • Built-in data libraries (breach DB, IP reputation)
  • Professional report formatting
  • High-value target prioritization
"""
    )
    # DEBUG: Before argparse.ArgumentParser
    parser.add_argument('type', choices=['username', 'email', 'domain', 'ip', 'person', 'phone', 'url'],
                        help='Target type')
    parser.add_argument('value', help='Target value')
    parser.add_argument('-D', '--depth', type=int, default=2,
                        help='Investigation depth (default: 2)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-o', '--output', help='Save to JSON file')
    parser.add_argument('--proxy', help='Proxy (http://host:port)')
    parser.add_argument('--browser', choices=['chrome', 'firefox'], default='chrome',
                        help='Browser for deep analysis')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('--no-consent', action='store_true', help='Skip consent prompt')
    
    args = parser.parse_args()
    
    # DEBUG: Before get_consent
    if not get_consent(args.no_consent):
        print(f"{Colors.FAIL}You must agree to the terms to use this tool.{Colors.ENDC}")
        sys.exit(1)
    # DEBUG: After get_consent, result: True (assuming yes)
    
    # DEBUG: Before print_banner
    if not args.no_banner:
        print_banner()
    
    # DEBUG: Before sites.json check
    # Check sites.json
    if not Path('sites.json').exists():
        print(f"{Colors.FAIL}ERROR: sites.json not found{Colors.ENDC}")
        sys.exit(1)
    
    # DEBUG: Before A1OSINT initialization
    # Initialize A1OSINT (Replaced ULTIMA with the correct class)
    hunter = A1OSINT(
        verbose=args.verbose,
        max_depth=args.depth,
        proxy=args.proxy,
        browser=args.browser
    )
    # DEBUG: After A1OSINT initialization
    
    try:
        # DEBUG: Before hunter.start()
        # Corrected static method call to instance method call
        nodes, statistics = hunter.start(args.type, args.value)
        # DEBUG: After hunter.start()
        
        # DEBUG: Before format_professional_report()
        # Display report
        report = format_professional_report(nodes, statistics)
        # DEBUG: After format_professional_report()
        
        # DEBUG: Before print(report)
        print(report)
        # DEBUG: After printing report
        
        # Save if requested
        if args.output:
            # DEBUG: Before saving output
            full_data = {
                'nodes': {k: v for k, v in nodes.items()},
                'statistics': statistics,
                'generated': datetime.now().isoformat()
            }
            with open(args.output, 'w') as f:
                json.dump(full_data, f, indent=2, default=str)
            print(f"{Colors.OKGREEN}Intelligence report saved: {args.output}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Investigation interrupted{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}Fatal error: {e}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    # DEBUG: End of main try block

if __name__ == '__main__':
    # DEBUG: Before main()
    main()