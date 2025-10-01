import streamlit as st
import pandas as pd
import re, os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
import openai
import matplotlib.pyplot as plt
from collections import Counter
from scipy.sparse import vstack

st.set_page_config(page_title="🛡️PhishGuard - Smart Phishing Detector", layout="wide")
st.markdown("""
<style>

div[data-baseweb="tab-list"] button {
    font-size: 3em;  
    font-weight: bold;
    color: #00ffff;    
}
div[data-baseweb="tab-list"] button[data-selected="true"] {
    color: #00ffcc;    
}

.stApp {
    background-color:#0d0d0d;
    color:#ffffff;
    background-image: 
        url('https://www.transparenttextures.com/patterns/cubes.png'), /* subtle cyber grid */
        url('https://cdn-icons-png.flaticon.com/512/3135/3135715.png'), /* top-left shield */
        url('https://cdn-icons-png.flaticon.com/512/281/281761.png'), /* bottom-left eye */
        url('https://cdn-icons-png.flaticon.com/512/3135/3135768.png'); /* bottom-right guard */
    background-repeat: repeat, no-repeat, no-repeat, no-repeat;
    background-position: center, 30px 30px, 30px calc(100% - 30px), calc(100% - 30px) calc(100% - 30px);
    background-size: auto, 80px, 80px, 80px;
}

/* Tabs Highlight with Neon Glow */
.css-1v3fvcr.e1fqkh3o3 button[aria-selected="true"] {
    background-color:#00ffcc !important; 
    color:#0d0d0d !important; 
    border-radius:10px 10px 0 0; 
    font-weight:bold;
    box-shadow: 0 0 15px #00ffcc, 0 0 30px #00ffcc, 0 0 45px #00ffcc;
    animation: neonGlow 2s ease-in-out infinite alternate;
}
@keyframes neonGlow {
    0% { box-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc, 0 0 30px #00ffcc; }
    100% { box-shadow: 0 0 25px #00ffcc, 0 0 50px #00ffcc, 0 0 75px #00ffcc; }
}
.css-1v3fvcr.e1fqkh3o3 button[aria-selected="false"] {
    background-color:#262626 !important; 
    color:#00ffcc !important; 
    border-radius:10px 10px 0 0; 
    opacity:0.7;
}
.css-1v3fvcr.e1fqkh3o3 button:hover {background-color:#00cccc !important; color:white !important;}

/* Animated icon top-right */
.top-right-animated {
    position: fixed;
    top: 20px;
    right: 20px;
    width: 90px;
    height: 90px;
    background-image: url('https://cdn-icons-png.flaticon.com/512/1031/1031660.png'); /* padlock */
    background-size: contain;
    background-repeat: no-repeat;
    animation: zoomFade 2s ease-in-out forwards, pulseGlow 3s infinite ease-in-out;
}

/* Entry animation */
@keyframes zoomFade {
    0% {opacity: 0; transform: scale(0.2) rotate(-45deg);}
    60% {opacity: 0.7; transform: scale(1.1) rotate(10deg);}
    100% {opacity: 1; transform: scale(1) rotate(0);}
}

/* Continuous glow */
@keyframes pulseGlow {
    0% {filter: drop-shadow(0 0 2px #00ffcc);}
    50% {filter: drop-shadow(0 0 15px #00ffff);}
    100% {filter: drop-shadow(0 0 2px #00ffcc);}
}

.stTitle {
    color:#00ffcc;
    text-align:center;
    font-size:3.5em;
    font-weight:bold;
    text-shadow: 2px 2px 5px #00ffff;
}

.stSubHeader {
    color:#ffffff;
    font-size:3em;
    text-align:center;
    margin-bottom:20px;
}

.stHeader {
    color:#00ffff;
    font-size:3.5em;
    margin-top:15px;
    text-shadow: 1px 1px 3px #00ffff;
}

.stMetric {
    background-color:#1a1a1a;
    padding:15px;
    border-radius:15px;
    font-size:2em;
    border: 1px solid #00ffcc;
}

.stTextInput>div>input, .stTextArea>div>textarea {
    background-color:#262626;
    color:#00ffcc;
    font-size:2em;
    padding:10px;
    border-radius:8px;
    border:1px solid #00ffcc;
}

.stButton>button {
    width:100%;
    background-color:#00ffcc;
    color:#0d0d0d;
    font-size:2em;
    padding:10px;
    border-radius:10px;
    font-weight:bold;
}

.stButton>button:hover {
    background-color:#00cccc;
    color:white;
}

.sidebar .stTextInput>input {
    background-color:#262626;
    color:#00ffcc;
    font-size:2em;
    padding:5px;
    border-radius:5px;
}

.stDataFrame {color:#00ffcc;}
</style>

<div class="top-right-animated"></div>
""", unsafe_allow_html=True)





# --------------------- Main Title & Tagline ---------------------
st.markdown('<h1 class="stTitle">🛡️PhishGuard - Smart Phishing Detector</h1>', unsafe_allow_html=True)
st.markdown('<h3 class="stSubHeader">✨We Handle the Phish. You Handle the Business. ✨</h3>', unsafe_allow_html=True)

# --------------------- Sidebar ---------------------
with st.sidebar:
    st.header("⚙️ Settings")
    api_key_input = st.text_input("OpenAI API Key (optional)", type="password")
    if api_key_input:
        openai.api_key = api_key_input
        st.success("API Key set!")
    else:
        st.warning("GPT features disabled. Enter API key to enable.")

    st.markdown("---")
    uploaded_file = st.file_uploader("Upload CSV dataset (CSEV_08.csv)", type=["csv"])
    st.markdown("**Default queries for Security Assistant:**")
    query_options = [
        "How to spot phishing emails?",
        "What are common phishing techniques?",
        "How to protect against phishing attacks?",
        "What to do if I receive a phishing email?",
        "How to identify fake websites?"
    ]

query_answers = {
    "How to spot phishing emails?": "Look for suspicious sender addresses, urgent language, misspelled URLs, or unexpected attachments. Always verify the source before clicking links.",
    "What are common phishing techniques?": "Common techniques include email spoofing, spear phishing, clone phishing, and using fake login pages to steal credentials.",
    "How to protect against phishing attacks?": "Use email filters, avoid clicking unknown links, enable two-factor authentication, and regularly update your software.",
    "What to do if I receive a phishing email?": "Do not click any links or download attachments. Report it to your IT department and delete the email immediately.",
    "How to identify fake websites?": "Check for HTTPS, look for spelling errors, verify the domain, and ensure the URL matches the official site."
}

# --------------------- Preprocessing ---------------------
def preprocess_text(text):
    text = str(text or "")
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^A-Za-z0-9\s]", "", text)
    return text.lower().strip()

def load_dataset(file):
    try:
        df = pd.read_csv(file)
    except Exception as e:
        st.error(f"Failed to load dataset: {e}")
        return pd.DataFrame(columns=["text","URL","Label"])
    if 'text' not in df.columns:
        parts=[]
        if 'subject' in df.columns: parts.append(df['subject'].astype(str).fillna(''))
        if 'body' in df.columns: parts.append(df['body'].astype(str).fillna(''))
        df['text'] = parts[0]+(" "+parts[1] if len(parts)>1 else "") if parts else ""
    if 'URL' not in df.columns:
        for c in ['urls','url','link']:
            if c in df.columns:
                df['URL']=df[c]
                break
        else: df['URL']=""
    if 'Label' not in df.columns:
        if 'label' in df.columns: df['Label']=df['label']
        else: df['Label']=0
    df = df[['text','URL','Label']].fillna('')
    df['text'] = df['text'].apply(preprocess_text)
    df['Label'] = pd.to_numeric(df['Label'], errors='coerce').fillna(0).astype(int)
    return df

# --------------------- Train Model ---------------------
def train_model(df):
    X = df['text'].tolist()
    y = df['Label'].values
    vect = TfidfVectorizer(max_features=2000, ngram_range=(1,2), stop_words='english')
    X_vect = vect.fit_transform(X)

    counts = Counter(y)
    for cls, cnt in counts.items():
        if cnt < 2:
            idx = [i for i, label in enumerate(y) if label == cls]
            X_dup = X_vect[idx]
            y_dup = [cls] * (2 - cnt)
            X_vect = vstack([X_vect, X_dup])
            y = list(y) + y_dup

    if len(set(y)) > 1:
        X_train, X_test, y_train, y_test = train_test_split(X_vect, y, test_size=0.2, random_state=42, stratify=y)
        base = LogisticRegression(max_iter=400, class_weight='balanced')
        base.fit(X_train, y_train)
        clf = CalibratedClassifierCV(base, cv='prefit', method='sigmoid')
        clf.fit(X_test, y_test)
    else:
        clf = LogisticRegression(max_iter=400, class_weight='balanced')
        clf.fit(X_vect, y)

    return clf, vect


LEGIT_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "live.com", "protonmail.com", "aol.com"
}

def detect_alphanumeric(word):
    word = str(word).lower()
    
    
    email_match = re.match(r"[\w\.-]+@([\w\.-]+)", word)
    if email_match:
        domain = email_match.group(1)
        if domain in LEGIT_EMAIL_DOMAINS:
            return False  
    
   
    return bool(re.search(r'[a-zA-Z]*[0-9]+[a-zA-Z]*', word))


# --------------------- Phishing Detection ---------------------
SUSPICIOUS_TLDS = {'.xyz','.top','.club','.loan','.review','.info','.site'}
DANGEROUS_EXTS = {'.exe','.scr','.bat','.js','.docm','.xlsm','.pptm','.msi'}

def detect_alphanumeric(word):
    return bool(re.search(r'[a-zA-Z]*[0-9]+[a-zA-Z]*', word))

def score_url(url):
    url = (url or "").lower()
    if not url: return 0.0
    score=0.0
    if any(tld in url for tld in SUSPICIOUS_TLDS): score+=0.5
    if detect_alphanumeric(url): score+=0.4
    if url.count('.')>3: score+=0.3
    return min(1.0,score)

def score_attachment(fname):
    fname=(fname or "").lower()
    if not fname: return 0.0
    ext=os.path.splitext(fname)[1]
    if ext in DANGEROUS_EXTS: return 0.9
    if detect_alphanumeric(fname): return 0.7
    return 0.1

def decide_phishing(text,url="",attachment=""):
    ml_proba=0.0
    if 'model' in st.session_state and 'vectorizer' in st.session_state:
        vec=st.session_state.vectorizer.transform([preprocess_text(text)])
        try: ml_proba=float(st.session_state.model.predict_proba(vec)[0][list(st.session_state.model.classes_).index(1)])
        except: ml_proba=0.0
    text_score=0.5 if detect_alphanumeric(text) else 0.0
    url_score=score_url(url)
    att_score=score_attachment(attachment)
    combined=ml_proba+text_score+url_score+att_score
    label=1 if combined>=0.6 else 0
    reasons=[]
    if ml_proba>=0.5: reasons.append("ml_confident")
    if text_score>=0.5: reasons.append("text_suspicious")
    if url_score>=0.5: reasons.append("url_suspicious")
    if att_score>=0.5: reasons.append("attachment_suspicious")
    if not reasons: reasons.append("low_confidence_safe")
    return {"label":label,"score":combined,"ml":ml_proba,"text_score":text_score,"url_score":url_score,"att_score":att_score,"reasons":reasons}

# --------------------- Tabs ---------------------
tab1, tab2, tab3 = st.tabs(["📩 Analyze Text", "📊 Recent Analysis", "🤖 Security Assistant"])

with tab1:
    st.markdown('<h2 class="stHeader">📩 Analyze Text</h2>', unsafe_allow_html=True)

    if "text_in" not in st.session_state: st.session_state.text_in = ""
    if "url_in" not in st.session_state: st.session_state.url_in = ""
    if "attachment_in" not in st.session_state: st.session_state.attachment_in = ""

    text_in = st.text_area("Paste email, SMS, or text here...", height=200, key="text_in")
    url_in = st.text_input("🔗 URL or email-like (e.g., xyz.c0m, example@gmail.exe)", key="url_in")
    attachment_in = st.text_input("📎 Upload Attachment (opt)", key="attachment_in")

    if st.button("🚀 Analyze"):
        if not text_in.strip(): st.warning("Enter some text to analyze.")
        else:
            res = decide_phishing(text_in, url_in, attachment_in)
            if res["label"]==1:
                st.error(f"🚨 PHISHING DETECTED")
                st.markdown(f'<div class="stMetric">Risk Score: <span style="color:#ff6b6b">{res["score"]:.2f}</span></div>', unsafe_allow_html=True)
            else:
                st.success(f"✅ SAFE CONTENT")
                st.markdown(f'<div class="stMetric">Risk Score: <span style="color:#4ecdc4">{res["score"]:.2f}</span></div>', unsafe_allow_html=True)

            if "recent_checks" not in st.session_state: st.session_state.recent_checks=[]
            st.session_state.recent_checks.insert(0,{"Text":text_in,"URL":url_in,"Attachment":attachment_in,"Score":res["score"],"Decision":"PHISHING" if res["label"]==1 else "SAFE"})
            st.session_state.recent_checks = st.session_state.recent_checks[:50]

with tab2:
    st.markdown('<h2 class="stHeader">📊 Recent Analysis</h2>', unsafe_allow_html=True)
    if "recent_checks" in st.session_state and st.session_state.recent_checks:
        df_recent = pd.DataFrame(st.session_state.recent_checks)
        st.dataframe(df_recent, use_container_width=True)
        st.markdown("### Decision Distribution")
        decision_counts = df_recent["Decision"].value_counts()
        colors = ["#4ecdc4" if d=="SAFE" else "#ff6b6b" for d in decision_counts.index]
        fig, ax = plt.subplots(figsize=(5,5))
        ax.pie(decision_counts, labels=decision_counts.index, colors=colors, autopct='%1.1f%%')
        ax.axis('equal')
        st.pyplot(fig)
    else:
        st.info("Analyze messages to see history!")

with tab3:
    st.markdown('<h2 class="stHeader">🤖 Security Assistant</h2>', unsafe_allow_html=True)
    user_q = st.text_input("Ask a security question or select default:", placeholder="Type your question here", key="user_q")
    selected_query = st.selectbox("Suggested Questions:", query_options)
    if selected_query and not user_q: user_q = selected_query

    if st.button("💬 Ask GPT"):
        if not user_q.strip(): st.warning("Enter a question.")
        else:
            if user_q in query_answers:
                answer = query_answers[user_q]
            else:
                try:
                    resp = openai.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role":"system","content":"You are a cybersecurity assistant focused on phishing prevention."},
                            {"role":"user","content":user_q}
                        ],
                        max_tokens=300, temperature=0.4
                    )
                    answer = resp.choices[0].message.content.strip()
                except Exception as e:
                    answer = f"Error: {str(e)}"
            st.info(answer)

# --------------------- Load & Train ---------------------
if uploaded_file:
    if 'model' not in st.session_state or 'vectorizer' not in st.session_state:
        with st.spinner("Loading dataset and training model..."):
            dataset = load_dataset(uploaded_file)
            model, vectorizer = train_model(dataset)
            st.session_state.model = model
            st.session_state.vectorizer = vectorizer
            st.success("✅ Model trained successfully!")
    else:
        st.info("Model trained Successfully!")
