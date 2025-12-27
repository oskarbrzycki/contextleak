  ContextLeak - AI Firewall Documentation import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs'; mermaid.initialize({ startOnLoad: true }); body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.6; color: #24292e; max-width: 900px; margin: 0 auto; padding: 40px 20px; } h1, h2, h3 { border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; margin-top: 24px; } h1 { font-size: 2em; border-bottom: none; } code { background-color: #f6f8fa; border-radius: 3px; padding: 0.2em 0.4em; font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace; font-size: 85%; } pre { background-color: #f6f8fa; padding: 16px; overflow: auto; border-radius: 6px; } pre code { background-color: transparent; padding: 0; font-size: 100%; } blockquote { border-left: 0.25em solid #dfe2e5; color: #6a737d; padding: 0 1em; margin: 0; } table { border-collapse: collapse; width: 100%; margin: 20px 0; } table th, table td { border: 1px solid #dfe2e5; padding: 6px 13px; } table tr:nth-child(2n) { background-color: #f6f8fa; } .badges img { margin-right: 5px; } .mermaid { text-align: center; margin: 30px 0; } .footer { text-align: center; margin-top: 50px; color: #586069; font-size: 0.9em; }

# ContextLeak 🛡️

![Python](https://img.shields.io/badge/python-3.11%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-success) ![Ollama](https://img.shields.io/badge/Supported-Ollama-orange)

> **The ultimate local firewall for LLM interactions. Prevent sensitive data leaks before they leave your machine.**

**ContextLeak** is an open-source, hybrid vulnerability scanner and input/output sanitizer designed for local AI environments (like Ollama/Llama 3). It acts as a bidirectional middleware between the user and the LLM, ensuring that PII (Personally Identifiable Information), API keys, and sensitive corporate data are redacted in real-time — both in your prompts and in the AI's responses.

- - -

## 📋 Table of Contents

*   [Key Features](#features)
*   [How It Works](#how-it-works)
*   [Installation](#installation)
*   [Quick Start](#quick-start)
*   [Configuration](#configuration)
*   [Roadmap](#roadmap)

- - -

## 🚀 Key Features

*   **🛡️ Bidirectional Protection**: Implements both **Input Filtering** (sanitizing prompts) and **Output Filtering** (sanitizing AI responses) to prevent the model from leaking training data or hallucinating PII.
*   **🧠 Hybrid Detection Engine**: Combines the power of NLP (Microsoft Presidio) with static analysis to minimize false negatives.
*   **🚫 PII Protection**: Automatically detects names, locations, emails, phone numbers, and more using the `en_core_web_lg` model.
*   **🔑 Secret Scanning**: Pre-configured Regex patterns to catch OpenAI keys, AWS credentials, and generic API tokens.
*   **📝 Custom Blocklists**: Easily define project-specific codenames (e.g., "ProjectX") that should never be mentioned to the AI.
*   **⚡ Zero-Latency Local Processing**: Optimized for local workflows. Your data is sanitized _locally_ before it's even processed by the model.
*   **📊 Audit Mode**: Scan existing logs or text files for potential leaks without running the chat.

- - -

## 🛠 How It Works

ContextLeak employs a **Closed-Loop Security Architecture**:

graph TD User([User]) -->|Raw Input| InFilter{Input Firewall} subgraph ContextLeak Protection InFilter -->|Safe Input| LLM["Local LLM / Llama 3"] LLM -->|Raw Response| OutFilter{Output Firewall} end OutFilter -->|Sanitized Response| User style InFilter fill:#ff9999,stroke:#333,stroke-width:2px style OutFilter fill:#99ff99,stroke:#333,stroke-width:2px

1.  **Input Filtering**: Before your prompt reaches Llama 3, it passes through Regex, Custom Blocklists, and Presidio NLP to strip sensitive data.
2.  **Processing**: The LLM receives only safe, redacted text (e.g., "My name is [REDACTED]").
3.  **Output Filtering**: The AI's response is scanned again before being displayed to you, preventing accidental leakage of memorized secrets or PII hallucinations.

- - -

## 📦 Installation

### Prerequisites

*   Python 3.10+
*   [Ollama](https://ollama.com/) (running locally)

### Step-by-Step

1. **Clone the repository:**

```
git clone https://github.com/oskarbrzycki/contextleak.git
cd contextleak
```

2. **Install in editable mode:**

```
pip install -e .
```

3. **Download the NLP Model:**

_ContextLeak relies on a large language model for accurate PII detection._

```
python -m spacy download en_core_web_lg
```

- - -

## ⚡ Quick Start

### 1. Interactive Chat (Protection Mode)

Start a secure session with your local Llama 3 model. Any sensitive data you type will be redacted before the model sees it.

```
python -m contextleak.cli chat
```

**Example:**

> **You:** My name is Oskar and my key is sk-12345.  
> **ContextLeak:** My name is [REDACTED: PERSON] and my key is [REDACTED: OPENAI_KEY].

### 2. Audit Mode

Scan a file for vulnerabilities without starting a chat. Useful for checking logs.

```
python -m contextleak.cli audit --file path/to/logs.txt
```

- - -

## ⚙ Configuration

ContextLeak works out of the box, but you can customize it via `config.json` (generated on first run) and `blocked_words.txt`.

### `config.json` parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| active_filters.email | bool | true | Detects email addresses. |
| active_filters.phone | bool | true | Detects phone numbers. |
| active_filters.person | bool | true | Uses NLP to detect names. |
| active_filters.openai_key | bool | true | Detects sk-... keys. |
| model_name | string | "llama3" | The local Ollama model to connect to. |

### Custom Blocklist

Create a file named `blocked_words.txt` in the root directory. Add one word/phrase per line.

```
ProjectZeus
InternalCodename
ManagerName
```

- - -

## 🗺 Roadmap

*   ✅ v1.0: Hybrid Engine (Presidio + Regex)
*   ✅ v1.0: CLI Chat Interface
*   ✅ v1.0: Bidirectional Guardrails (Input/Output filtering)
*   ⬜ v1.1: Support for PDF/DOCX file scanning
*   ⬜ v1.2: GUI (Graphical User Interface)
*   ⬜ v1.3: Docker Container support

- - -

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

- - -

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

Built with ❤️ by Oskar Brzycki