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
from bs4 import BeautifulSoup
import hashlib
from collections import deque
import robotexclusionrulesparser

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
    ║  █████╗  ██╗ ██████╗ ███████╗██╗███╗   ██╗████████╗║
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
        # This would load from a local breach database file
        # For now, returns empty - user can populate
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
                followers_el = self.driver.find_element(By.XPATH, "//a[contains(@href, 'followers')]/span")
                data['profile']['followers'] = followers_el.text.strip()
            except: pass
            
            try:
                following_el = self.driver.find_element(By.XPATH, "//a[contains(@href, 'following')]/span")
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
                comment_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-testid="comment"] ')[:15]
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
                followers_el = self.driver.find_element(By.XPATH, "//a[contains(@href, '/followers/')]//span")
                data['profile']['followers'] = followers_el.text.strip()
            except: pass
            
            try:
                following_el = self.driver.find_element(By.XPATH, "//a[contains(@href, '/following/')]//span")
                data['profile']['following'] = following_el.text.strip()
            except: pass
            
            # Post links
            try:
                post_links = self.driver.find_elements(By.CSS_SELECTOR, 'article a[href*="/p/"]')[:9]
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
                video_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-e2e="user-post-item"] ')[:12]
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
                post_elements = self.driver.find_elements(By.CSS_SELECTOR, 'div[data-ad-preview="message"] ')[:5]
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

class ULTIMA:
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
            'url': re.compile(r'https?://[^\s<>"{}|\\^\[\]]+'),