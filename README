# 🎣 Phishing Detector

A Streamlit app that checks a suspicious email, message or link with Google Gemini Flash plus rule-based security checks, and returns:

- a **phishing risk score** (0-100) and a clear verdict
- the **red flags** found, with evidence and an explanation of each
- **automated checks** on links, sender, Reply-To, SPF/DKIM/DMARC results and attachments
- **recommended actions** and a downloadable Markdown report

> Automated analysis can be wrong. A low score is not proof a message is safe. When in doubt, contact the organisation using contact details you find yourself, not the ones in the message.

## How it works

1. You paste the message or URL, or upload a `.eml` / `.txt` file.
2. The app extracts the sender, subject, body, links (including hidden link targets in HTML emails), attachment names and authentication headers.
3. **Rule-based checks** run locally: raw IP links, look-alike and punycode domains, brand impersonation (for example `paypal.com.evil.xyz`), `@` tricks in URLs, shortened links, link text that does not match its real destination, sender display-name spoofing, Reply-To mismatch, failed SPF/DKIM/DMARC, risky attachment types, urgent language and requests for sensitive information.
4. **Gemini** reads the message and returns a risk score, red flags and advice as structured JSON.
5. The final score blends both: 65% AI and 35% rules. A floor based on the rule score means the AI cannot be talked into a low score by hidden instructions inside a phishing email.

### Safety by design

- Links are **never opened or fetched** by the app.
- Links are shown **defanged** (`hxxps://evil[.]com`) so they cannot be clicked by accident.
- The email text is treated as untrusted data in the AI prompt.

## Run locally

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Get a free API key at https://aistudio.google.com/apikey, then either paste it into the sidebar or store it as a secret.

### Store the key as a secret (recommended)

Create `.streamlit/secrets.toml` (never commit this file):

```toml
GEMINI_API_KEY = "your-key-here"
```

The app looks for the key in this order: sidebar input, Streamlit secrets, `GEMINI_API_KEY` environment variable.

## Get a .eml file

- **Gmail:** open the email, click the three dots, then **Download message**.
- **Outlook (desktop):** drag the email to your desktop, or **File → Save As** and choose `.eml`/`.msg` (`.eml` works best).
- **Apple Mail:** drag the message to the desktop.

Using `.eml` gives the most accurate results because it includes headers and hidden link targets.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub (`app.py`, `requirements.txt`, `README.md` in the root).
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, choose your repo, branch `main`, main file `app.py`.
4. Open **Advanced settings → Secrets** and add: `GEMINI_API_KEY = "your-key-here"`
5. Click **Deploy**.

## Models

The sidebar offers a few Gemini Flash models plus a **Custom...** option. Model names change over time; if you see "model not found", check https://ai.google.dev/gemini-api/docs/models and enter a current name under Custom.

## Troubleshooting

| Problem | Fix |
|---|---|
| "API key was rejected" | Re-copy the key from Google AI Studio; check there are no spaces. |
| "Rate limit or quota reached" | Wait a minute, or switch model. The free tier has low limits. |
| "Model not found" | Pick another model, or use Custom... with a current model name. |
| "Empty response (may have been blocked)" | Try again, or paste less content. |

## Privacy

The message text is sent to Google's Gemini API. The app itself stores nothing. Remove passwords, one-time codes and card numbers before pasting. A public deployment with your own API key lets other people use your quota.

## Limitations

- No live reputation lookups (VirusTotal, Google Safe Browsing) and no domain-age checks; the app never contacts the links.
- Attachments are checked by file name and type only, not scanned.
- The brand list is limited. A message impersonating a brand not on the list relies mainly on the AI.

## Project structure

```
app.py             # Streamlit UI + rule-based checks + Gemini logic
requirements.txt   # Python dependencies
README.md
```
