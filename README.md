

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

ContextLeak sits between you and the local LLM, acting as a **bidirectional firewall**. The data flow consists of four steps:

1.  **User Input** 👤 → **ContextLeak Engine** 🛡️
    * You type a prompt (e.g., "My API key is sk-123...").
    * The engine instantly scans it using **Regex** (for structural secrets), **Custom Blocklists** (for project names), and **Presidio NLP** (for context-aware PII).

2.  **Input Sanitization** 🧹
    * Sensitive data is replaced with safe placeholders like `[REDACTED: OPENAI_KEY]`.
    * **Crucial Step:** The raw secret *never* reaches the AI model.

3.  **LLM Processing** 🤖
    * The local model (Llama 3) receives only the sanitized text. It generates a response based on safe data.

4.  **Output Filtering & Response** 💬
    * Before the AI's answer is shown to you, ContextLeak scans it again.
    * This prevents the model from accidentally leaking memorized data or hallucinating sensitive information.

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