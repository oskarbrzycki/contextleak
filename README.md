# ContextLeak 🛡️

![Tests](https://github.com/oskarbrzycki/contextleak/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-success)
![Ollama](https://img.shields.io/badge/Supported-Ollama-orange)

> **The ultimate local firewall for LLM interactions. Prevent sensitive data leaks before they leave your machine.**

**ContextLeak** is an open-source, hybrid vulnerability scanner and input sanitizer designed for local AI environments (like Ollama/Llama 3). It acts as a middleware between the user and the LLM, ensuring that PII (Personally Identifiable Information), API keys, and sensitive corporate data are redacted in real-time.

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Development & Testing](#-development--testing)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Key Features

* **🧠 Hybrid Detection Engine**: Combines the power of NLP (Microsoft Presidio) with static analysis to minimize false negatives.
* **🚫 PII Protection**: Automatically detects names, locations, emails, phone numbers, and more using the `en_core_web_lg` model.
* **🔑 Secret Scanning**: Pre-configured Regex patterns to catch OpenAI keys, AWS credentials, and generic API tokens.
* **📝 Custom Blocklists**: Easily define project-specific codenames (e.g., "ProjectX") that should never be mentioned to the AI.
* **⚡ Zero-Latency Local Processing**: Optimized for local workflows. Your data is sanitized *locally* before it's even processed by the model.
* **📊 Audit Mode**: Scan existing logs or text files for potential leaks without running the chat.

---

## 🛠 How It Works

ContextLeak employs a **Layered Security Architecture**:

```mermaid
graph LR
    A["User Input"] --> B{"Layer 1: Regex"}
    B --> C{"Layer 2: Custom Blocklist"}
    C --> D{"Layer 3: Presidio NLP"}
    D --> E["Sanitized Input"]
    E --> F["LLM (Llama 3)"]