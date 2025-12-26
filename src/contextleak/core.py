import json
import urllib.request
import urllib.error
import re
import os  # Needed for file operations

class ContextLeakCore:
    def __init__(self, model_name="llama3", system_prompt=None):
        """
        Initializes the ContextLeak engine.
        Features:
        - Regex Pattern Database
        - Config Persistence (config.json)
        - Custom Blocklist (blocked_words.txt)
        """
        self.model_name = model_name
        self.api_url = "http://localhost:11434/api/chat"
        self.history = []
        self.config_file = "config.json"
        self.custom_list_file = "blocked_words.txt"
        
        # Default system prompt
        self.system_prompt = system_prompt or (
            "You are a security-focused AI assistant for the Open Source project 'ContextLeak'. "
            "You help users detect vulnerabilities. Be precise and technical."
        )

        # === REGEX PATTERN DATABASE ===
        self.PATTERNS = {
            # Keys & Secrets
            "openai_key": r'sk-[a-zA-Z0-9]{20,}',
            "aws_key": r'(AKIA|ASIA)[0-9A-Z]{16}',
            "private_key": r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            "generic_secret": r'(?i)(api_key|secret|token)\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
            # PII
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone_number": r'(?<!\d)(?:\+?\d{1,3}[-\s]?)?(?:(?:\d{3}[-\s]?){3})(?!\d)', 
            # Finance
            "credit_card": r'\b(?:\d[ -]*?){13,16}\b',
            "crypto_btc": r'\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b',
            "crypto_eth": r'\b0x[a-fA-F0-9]{40}\b',
            # Infrastructure
            "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "mac_address": r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        }

        # Initialize configuration (Load from file or set defaults)
        self.active_filters = self._load_config()
        
        # Load custom blocked words
        self.custom_patterns = self._load_custom_list()

    def _load_config(self):
        """Feature B: Load filter settings from config.json"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    print(f"[System]: Loaded configuration from {self.config_file}")
                    return json.load(f)
            except Exception as e:
                print(f"[Error]: Failed to load config: {e}")
        
        # Default: Enable all filters
        return {key: True for key in self.PATTERNS.keys()}

    def _save_config(self):
        """Feature B: Save current settings to config.json"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.active_filters, f, indent=4)
        except Exception as e:
            print(f"[Error]: Failed to save config: {e}")

    def _load_custom_list(self):
        """Feature C: Load custom words from blocked_words.txt"""
        patterns = []
        if os.path.exists(self.custom_list_file):
            try:
                with open(self.custom_list_file, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f if line.strip()]
                    if words:
                        # Create a single compiled regex for all custom words (Case Insensitive)
                        # We use re.escape to handle special characters safely
                        pattern_str = '|'.join(map(re.escape, words))
                        print(f"[System]: Loaded {len(words)} custom blocked words.")
                        return re.compile(pattern_str, re.IGNORECASE)
            except Exception as e:
                print(f"[Error]: Failed to load custom list: {e}")
        return None

    def toggle_filter(self, filter_name):
        """Toggles a filter and SAVES the state."""
        if filter_name in self.active_filters:
            self.active_filters[filter_name] = not self.active_filters[filter_name]
            self._save_config()  # <--- SAVE IMMEDIATELY
            state = "ON" if self.active_filters[filter_name] else "OFF"
            return f"Filter '{filter_name}' is now {state} (Saved)."
        else:
            return f"Error: Filter '{filter_name}' not found."

    def get_filter_status(self):
        status = "\n=== SECURITY FILTERS STATUS ===\n"
        for name, is_active in self.active_filters.items():
            icon = "[ON] " if is_active else "[OFF]"
            status += f"{icon} {name}\n"
        
        if self.custom_patterns:
            status += "[ON]  CUSTOM_BLOCKLIST (from file)\n"
        else:
            status += "[OFF] CUSTOM_BLOCKLIST (file not found)\n"
        return status

    def _sanitize_text(self, text):
        if not text: return text
        
        clean_text = text
        
        # 1. Apply Standard Patterns
        for name, pattern in self.PATTERNS.items():
            if self.active_filters.get(name):
                replacement = f'[REDACTED: {name.upper()}]'
                clean_text = re.sub(pattern, replacement, clean_text)

        # 2. Apply Custom Patterns (Feature C)
        if self.custom_patterns:
            # Replaces any custom word with [REDACTED: CUSTOM]
            clean_text = self.custom_patterns.sub('[REDACTED: CUSTOM]', clean_text)
                
        return clean_text

    def chat(self, user_input):
        if not user_input.strip():
            return "Error: Empty input."

        # Input Sanitization
        safe_input = self._sanitize_text(user_input)
        if safe_input != user_input:
            print(f"\n[ContextLeak SECURITY]: Sensitive data detected and redacted from your input.")

        self.history.append({"role": "user", "content": safe_input})

        messages = [{'role': 'system', 'content': self.system_prompt}] + self.history
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.api_url, 
                data=data, 
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req) as response:
                result_json = json.loads(response.read().decode('utf-8'))
                bot_response = result_json.get('message', {}).get('content', '')
                
                if not bot_response:
                    return "Error: Empty response."

                # Output Sanitization
                safe_response = self._sanitize_text(bot_response)

                # Hacker Alert Logic
                if safe_response != bot_response:
                    print("\n" + "!"*50)
                    print("🚨 SECURITY INCIDENT PREVENTED! 🚨")
                    print("The AI attempted to share sensitive data.")
                    print("ContextLeak firewall blocked it just in time.")
                    print("!"*50 + "\n")

                self.history.append({"role": "assistant", "content": safe_response})
                return safe_response

        except urllib.error.URLError:
            return "Connection Error: Is Ollama running?"
        except Exception as e:
            return f"Unexpected Error: {str(e)}"

    def clear_context(self):
        self.history = []
        return "Memory cleared."