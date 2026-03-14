# PhishGuard — AI Phishing Detection Suite

PhishGuard is a comprehensive, multi-modal AI phishing detection suite consisting of a **Python FastAPI Backend** and a **Chrome Extension + Web Dashboard Frontend**. It uses a blend of Machine Learning, Heuristics, and Generative AI (Google Gemini) to detect threats across URLs, emails, images, and PDF documents.

---

## 🏛️ 1. Architecture & Tech Stack

*   **Backend:** Python 3, FastAPI, Uvicorn, Scikit-learn, Google Gemini AI (`gemini-2.0-flash`), PyMuPDF (PDF extraction), python-whois (Domain lookup).
*   **Web Dashboard:** HTML5, Vanilla JavaScript (ES6+), Vanilla CSS3 (Glassmorphism & animations).
*   **Browser Extension:** Chrome Manifest V3, Service Workers, Content Scripts, DOM Manipulation.

---

## 🧠 2. Detection Logic & Engines

PhishGuard leverages four layers of analysis to determine if a URL, email, or file is safe:

### A. URL Analysis (`url_analyzer.py` & `model.py`)
1.  **Lexical Heuristics (Rule-based):** Checks over 20+ red flags instantly.
    *   *Examples:* Does it use an IP address instead of a domain? Is it abnormally long? Does it have multiple `@` or `-` symbols? Are there suspicious keywords like "login" or "verify"? Does it use a URL shortener?
2.  **Machine Learning Model:** A trained Random Forest Classifier (`model.pkl`) evaluates the heuristic features and outputs an ML confidence score.
3.  **Domain Reputation (Deep Scan):** Uses `python-whois` to check the domain registration date. If a domain is less than 30 days old ("newly registered domain"), the risk score spikes dramatically.
4.  **Redirect Tracing (Deep Scan):** Follows the HTTP chain to see where the URL *actually* goes, uncovering hidden phishing pages.

### B. Email Text Analysis (`email_analyzer.py`)
1.  **NLP Term Frequency:** Scans the text for high-risk words (e.g., "urgent", "account suspended", "click here", "password").
2.  **Urgency Hooks:** Detects psychological manipulation tactics.
3.  **Link Extraction:** Uses RegEx to pull every URL out of the email body and scores the email based on the risk level of the embedded links.

### C. Document & Vision Analysis (`advanced_analyzer.py`)
1.  **Visual Phishing (Images):** Sends screenshots or images to Gemini AI Vision to "look" at the page (e.g., spotting a fake Microsoft login screen that evades text scanners).
2.  **PDF Scanning:** Uses `PyMuPDF` to extract text from PDFs (common for "Fake Invoice" scams) and feeds the text to Gemini AI to analyze intent.

### D. Gemini LLM Explanations (`llm_agent.py` & `/api/explain`)
Instead of just returning a numerical score, the backend passes the gathered signals to Gemini AI to generate a **3-5 bullet plain-English explanation** of *why* the content is dangerous and what the user should do.

---

## 🧩 3. The Chrome Extension

The extension (`Manifest V3`) actively protects the user in real-time.

*   **Background Scanner (`background.js`):** Silently intercepts tabs as they load. If the `auto_scan` setting is on, it sends the URL to the FastAPI backend.
*   **Badge & Notifications:** Changes the extension icon to Green, Yellow (!), or Red (!!). Sends native Chrome push notifications for dangerous sites.
*   **Active Blocker:**
    *   If a site scores **≥ 50**, the tab is immediately redirected to a glowing red `block.html` warning page before the phishing script can load.
    *   Intercepts and blocks **Anonymous Redirects** (e.g., `bit.ly`, `grabify.link`, `proxysite.com`) using `chrome.webNavigation.onCommitted`.
*   **Gmail Integration (`gmail_chat.js`):** Injects a floating "Analyze Email" sidebar directly into `mail.google.com`. It reads the DOM of the open email and streams an AI conversational analysis.
*   **Context Menu:** Right-click any link on the web and select "Scan link with PhishGuard".

---

## 🌐 4. The Web Dashboard

The central hub accessed via `http://localhost:8000`.

*   **Multi-Tab Interface:** Separate drop-zones and inputs for URLs, Emails, and PDF Documents.
*   **Animated Risk Gauge:** An SVG dashboard gauge that animates from 0 to 100 based on the backend risk score.
*   **Feature Transparency Grid:** An accordion that shows exactly which heuristic rules flagged true (e.g., `Using_IP: 0`, `Has_Suspicious_Words: 1`).
*   **AI Chatbot:** A locally hosted, dark-themed floating widget that maintains conversation history and lets the user ask general cybersecurity questions directly to Gemini.
*   **History & Stats:** Uses `localStorage` to keep a rolling list of recent scans, and syncs with the `/api/stats` endpoint to show global metrics (Total Scans, Threats Caught).

---

## 🔒 5. Storage & Privacy

*   **Local Storage:** All user history and settings (auto-scan toggles, blocklists) are stored locally in the browser (`chrome.storage.local` and `window.localStorage`).
*   **API Security:** The only external API hit is Google Gemini (via the `.env` provided `GEMINI_API_KEY`). All ML and heuristic math is done locally on your FastAPI server.

---

*© 2026 Anagh Khandelwal — PhishGuard Developer Documentation*
