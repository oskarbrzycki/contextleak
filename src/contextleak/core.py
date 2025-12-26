import json
import urllib.request
import urllib.error
import re
import os
import sys

# --- MICROSOFT PRESIDIO IMPORTS ---
try:
    import spacy
    import spacy.cli
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
except ImportError:
    print("\n[CRITICAL ERROR]: Missing required libraries!")
    print("Please run: pip install presidio-analyzer presidio-anonymizer spacy\n")
    sys.exit(1)

class ContextLeakCore:
    def __init__(self, model_name="llama3", system_prompt=None):
        """
        Initializes the ContextLeak engine with Hybrid Detection (Presidio AI + Regex).
        """
        self.model_name = model_name
        self.api_url = "http://localhost:11434/api/chat"
        self.history = []
        self.config_file = "config.json"
        self.custom_list_file = "blocked_words.txt"
        
        # --- 1. AI ENGINE SETUP (PRESIDIO) ---
        print("[System]: Initializing AI Firewall engine (Microsoft Presidio)...")
        self._ensure_spacy_model() # Check/Download model
        
        # Load engines (this might take 1-2 seconds)
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

        # Mapping: User Filter Name -> Presidio Entity
        self.PRESIDIO_MAPPING = {
            "email": "EMAIL_ADDRESS",
            "phone_number": "PHONE_NUMBER",
            "ip_address": "IP_ADDRESS",
            "credit_card": "CREDIT_CARD",
            "crypto_wallet": "CRYPTO",
            "person": "PERSON",           # Detects names (Contextual)
            "location": "LOCATION",       # Detects cities/countries (Contextual)
            "medical_license": "MEDICAL_LICENSE"
        }

        # --- 2. REGEX DATABASE SETUP (Technical Secrets Only) ---
        # Presidio is great for NLP, but Regex is better for rigid key formats.
        self.REGEX_PATTERNS = {
            "openai_key": r'sk-[a-zA-Z0-9]{20,}',
            "aws_key": r'(AKIA|ASIA)[0-9A-Z]{16}',
            "private_key": r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "generic_secret": r'(?i)(api_key|secret|token)\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?'
        }

        self.system_prompt = system_prompt or (
            "You are a security-focused AI assistant for the Open Source project 'ContextLeak'. "
            "You help users detect vulnerabilities. Be precise and technical."
        )

        # Load configurations
        self.active_filters = self._load_config()
        self.custom_patterns = self._load_custom_list()

    def _ensure_spacy_model(self):
        """Automatically checks for and downloads the NLP model if missing."""
        model_name = "en_core_web_lg"
        if not spacy.util.is_package(model_name):
            print(f"[Install]: NLP model '{model_name}' not found.")
            print(f"[Install]: Downloading model (~500MB) - this is a one-time operation...")
            try:
                spacy.cli.download(model_name)
                print("[Install]: Model downloaded successfully.")
                # Reload spacy to recognize the new model
                import en_core_web_lg
                en_core_web_lg.load()
            except Exception as e:
                print(f"[Error]: Automatic download failed. Please run manually: python -m spacy download {model_name}")
                raise e

    def _load_config(self):
        """Loads filter settings from config.json, merging Presidio and Regex keys."""
        all_keys = list(self.PRESIDIO_MAPPING.keys()) + list(self.REGEX_PATTERNS.keys())
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    print(f"[System]: Configuration loaded from {self.config_file}")
                    # Merge: File settings + defaults for new keys
                    return {k: loaded_config.get(k, True) for k in all_keys}
            except Exception as e:
                print(f"[Error]: Failed to load config: {e}")
        
        # Default: Enable all
        return {key: True for key in all_keys}

    def _save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.active_filters, f, indent=4)
        except Exception as e:
            print(f"[Error]: Failed to save config: {e}")

    def _load_custom_list(self):
        if os.path.exists(self.custom_list_file):
            try:
                with open(self.custom_list_file, 'r', encoding='utf-8') as f:
                    words = [line.strip() for line in f if line.strip()]
                    if words:
                        pattern_str = '|'.join(map(re.escape, words))
                        print(f"[System]: Loaded {len(words)} custom blocked words.")
                        return re.compile(pattern_str, re.IGNORECASE)
            except Exception as e:
                print(f"[Error]: Failed to load blocked_words.txt: {e}")
        return None

    def toggle_filter(self, filter_name):
        if filter_name in self.active_filters:
            self.active_filters[filter_name] = not self.active_filters[filter_name]
            self._save_config()
            state = "ON" if self.active_filters[filter_name] else "OFF"
            return f"Filter '{filter_name}' is now {state} (Saved)."
        else:
            return f"Error: Filter '{filter_name}' does not exist."

    def get_filter_status(self):
        status = "\n=== SECURITY STATUS (AI + REGEX) ===\n"
        
        status += "--- Contextual Analysis (Presidio AI) ---\n"
        for key in self.PRESIDIO_MAPPING.keys():
            icon = "[ON] " if self.active_filters.get(key, True) else "[OFF]"
            status += f"{icon} {key}\n"
            
        status += "\n--- Static Rules (Regex) ---\n"
        for key in self.REGEX_PATTERNS.keys():
            icon = "[ON] " if self.active_filters.get(key, True) else "[OFF]"
            status += f"{icon} {key}\n"

        if self.custom_patterns:
            status += "\n[ON]  CUSTOM_BLOCKLIST (active)\n"
        else:
            status += "\n[OFF] CUSTOM_BLOCKLIST (file missing/empty)\n"
        return status

    def _sanitize_text(self, text):
        """
        MAIN SCANNING ENGINE (HYBRID)
        1. Presidio (NLP) -> Detects PII (names, emails, locations)
        2. Regex -> Detects API keys and technical secrets
        3. Custom Blocklist -> User defined words
        """
        if not text: return text
        
        clean_text = text

        # --- STEP 1: MICROSOFT PRESIDIO (NLP) ---
        # Select active entities from config
        active_presidio_entities = []
        for config_key, presidio_entity in self.PRESIDIO_MAPPING.items():
            if self.active_filters.get(config_key, False):
                active_presidio_entities.append(presidio_entity)

        if active_presidio_entities:
            try:
                # Analyze
                results = self.analyzer.analyze(
                    text=clean_text,
                    entities=active_presidio_entities,
                    language='en'
                )
                
                # Anonymize
                if results:
                    anonymized_result = self.anonymizer.anonymize(
                        text=clean_text,
                        analyzer_results=results,
                        operators={
                            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED: PII]"})
                        }
                    )
                    clean_text = anonymized_result.text
            except Exception:
                # In production, we might want to log this silently or pass
                pass

        # --- STEP 2: STATIC REGEX PATTERNS (Secrets) ---
        for name, pattern in self.REGEX_PATTERNS.items():
            if self.active_filters.get(name):
                replacement = f'[REDACTED: {name.upper()}]'
                clean_text = re.sub(pattern, replacement, clean_text)

        # --- STEP 3: CUSTOM BLOCKLIST ---
        if self.custom_patterns:
            clean_text = self.custom_patterns.sub('[REDACTED: CUSTOM]', clean_text)
                
        return clean_text

    def chat(self, user_input):
        if not user_input.strip():
            return "Error: Empty input."

        # Input Sanitization (Protect against sending sensitive data to cloud/model)
        safe_input = self._sanitize_text(user_input)
        
        # Log incident on user side
        if safe_input != user_input:
            print(f"\n[ContextLeak SECURITY]: Sensitive data detected! It was redacted before sending.")

        self.history.append({"role": "user", "content": safe_input})

        messages = [{'role': 'system', 'content': self.system_prompt}] + self.history
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False
        }

        try:
            # Using standard urllib to avoid extra 'requests' dependency if not needed
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
                    return "Error: Empty response from model."

                # Output Sanitization (Outbound Firewall - in case model leaks data)
                safe_response = self._sanitize_text(bot_response)

                # Incident Detection
                if safe_response != bot_response:
                    print("\n" + "!"*50)
                    print("🚨 SECURITY INCIDENT PREVENTED! 🚨")
                    print("The AI model attempted to leak sensitive data (PII/Secrets).")
                    print("ContextLeak firewall blocked this fragment.")
                    print("!"*50 + "\n")

                self.history.append({"role": "assistant", "content": safe_response})
                return safe_response

        except urllib.error.URLError:
            return "Connection Error: Is Ollama running? (localhost:11434)"
        except Exception as e:
            return f"Unexpected Error: {str(e)}"

    def clear_context(self):
        self.history = []
        return "Context memory cleared."