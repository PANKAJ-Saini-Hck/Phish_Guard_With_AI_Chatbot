# 🛡️ PhishGuard - Smart Phishing Detector

PhishGuard is a **real-time phishing detection tool** built with Python and Streamlit. It uses machine learning, heuristic scoring, and OpenAI GPT-powered insights to analyze emails, URLs, and attachments for phishing attempts. The app also includes a **Security Assistant** to answer common cybersecurity questions.

---

## 🚀 Features

### 1. Analyze Text
- Detects phishing in emails, SMS, or other text messages.
- Scores content based on:
  - ML model confidence.
  - Suspicious URLs and attachments.
  - Presence of alphanumeric patterns commonly used in phishing.
- Provides a combined risk score and decision (SAFE or PHISHING).

### 2. Recent Analysis
- Maintains a history of recent analyses.
- Displays decisions in a table.
- Visualizes **decision distribution** with a pie chart.

### 3. Security Assistant (GPT)
- Ask predefined or custom security questions.
- Provides guidance using:
  - Built-in curated responses.
  - OpenAI GPT (optional, requires API key).

### 4. Machine Learning Model
- Uses **TF-IDF Vectorizer** + **Logistic Regression**.
- Handles small datasets and class imbalance.
- Custom preprocessing of text and URLs.

### 5. Heuristic Scoring
- Suspicious TLDs (`.xyz`, `.top`, `.club`) and dangerous file extensions (`.exe`, `.bat`, etc.) are scored.
- Combination of ML prediction and heuristic rules provides robust detection.

### 6. Custom UI
- Streamlit app with **neon cyber-style theme**.
- Animated icons and tabs for better UX.

---

## 🛠️ Tech Stack
- **Frontend:** Streamlit  
- **Backend:** Python 3, scikit-learn, pandas, numpy  
- **ML:** Logistic Regression, TF-IDF vectorization, calibrated classifier  
- **Visualization:** Matplotlib, Streamlit dataframes  
- **AI Integration:** OpenAI GPT-3.5-turbo (optional)

---

## 📥 Installation

1. Clone the repository:

```bash
git clone https://github.com/PANKAJ-Saini-Hck/Phish_Guard_With_AI_Chatbot.git
cd Phish_Guard_With_AI_Chatbot
