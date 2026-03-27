# from flask import Flask, render_template, request
# import pickle
# import re

# app = Flask(__name__)

# vector = pickle.load(open("vectorizer.pkl", 'rb'))
# model = pickle.load(open("phishing.pkl", 'rb'))


# @app.route("/", methods=['GET', 'POST'])
# def index():
#     if request.method == "POST":
#         url = request.form['url']
#         # print(url)
        
#         cleaned_url = re.sub(r'^https?://(www\.)?', '', url)
#         # print(cleaned_url)
        
#         predict = model.predict(vector.transform([cleaned_url]))[0]
#         # print(predict)
        
#         if predict == 'bad':
#             predict = "This is a Phishing website !!"
#         elif predict == 'good':
#             predict = "This is healthy and good website !!"
#         else:
#             predict = "Something went wrong !!"
        
#         return render_template("index.html", predict=predict)
    
#     else:
#         return render_template("index.html")



# if __name__=="__main__":
#     app.run(debug=True)












# from flask import Flask, render_template, request
# import pickle
# import re
# import numpy as np

# app = Flask(__name__)

# # Load model and vectorizer
# vector = pickle.load(open("vectorizer.pkl", 'rb'))
# model = pickle.load(open("phishing.pkl", 'rb'))

# @app.route("/", methods=['GET', 'POST'])
# def index():
#     predict = None
#     explanation = []
#     url_input = ""

#     if request.method == "POST":
#         url_input = request.form['url']
#         cleaned_url = re.sub(r'^https?://(www\.)?', '', url_input)

#         # Prediction
#         X = vector.transform([cleaned_url])
#         pred_label = model.predict(X)[0]

#         # Confidence (requires model to have predict_proba)
#         try:
#             prob = model.predict_proba(X)[0]
#             confidence = np.max(prob) * 100
#         except AttributeError:
#             # fallback if model doesn't have predict_proba
#             confidence = 90.0  # just a placeholder

#         if pred_label == 'bad':
#             predict = f"This site is Phishing ({confidence:.2f}%)"
#         elif pred_label == 'good':
#             predict = f"This site is Safe ({confidence:.2f}%)"
#         else:
#             predict = "Something went wrong !!"

#         # Explanation factors
#         if "http://" in url_input:
#             explanation.append("URL uses HTTP instead of HTTPS")
#         if len(url_input) > 30:
#             explanation.append("URL length is unusually long")
#         if any(c in url_input for c in ["@", "%", "$"]):
#             explanation.append("Suspicious characters detected")
#         if pred_label == 'bad' and not explanation:
#             explanation.append("Predicted phishing based on model patterns")

#     return render_template("index.html", 
#                            predict=predict, 
#                            explanation=explanation, 
#                            url_input=url_input)


# if __name__=="__main__":
#     app.run(debug=True)











# from flask import Flask, render_template, request
# import pickle
# import re
# import numpy as np
# from nltk.tokenize import RegexpTokenizer
# from nltk.stem.snowball import SnowballStemmer

# app = Flask(__name__)

# # Load trained model and vectorizer
# vectorizer = pickle.load(open("vectorizer.pkl", 'rb'))
# model = pickle.load(open("phishing.pkl", 'rb'))

# # Tokenizer and stemmer must match your notebook preprocessing
# tokenizer = RegexpTokenizer(r'[A-Za-z]+')
# stemmer = SnowballStemmer('english')

# def preprocess_url(url):
#     """Clean, tokenize, and stem a URL"""
#     url_clean = re.sub(r'^https?://(www\.)?', '', url)
#     tokens = tokenizer.tokenize(url_clean)
#     stemmed = [stemmer.stem(t) for t in tokens]
#     return ' '.join(stemmed)

# @app.route("/", methods=['GET','POST'])
# def home():
#     predict = None
#     explanation = []
#     url_input = ""
    
#     if request.method == "POST":
#         url_input = request.form['url']
#         processed_url = preprocess_url(url_input)
        
#         # Vectorize URL for model
#         X = vectorizer.transform([processed_url])
#         pred_label = model.predict(X)[0]
        
#         # Confidence
#         try:
#             confidence = np.max(model.predict_proba(X)[0]) * 100
#         except AttributeError:
#             confidence = 90.0
        
#         # Prediction message
#         if pred_label == 'bad':
#             predict = f"This site is Phishing ({confidence:.2f}%)"
#         else:
#             predict = f"This site is Safe ({confidence:.2f}%)"
        
#         # Explanation
#         if "http://" in url_input:
#             explanation.append("URL uses HTTP instead of HTTPS")
#         if len(url_input) > 30:
#             explanation.append("URL length is unusually long")
#         if any(c in url_input for c in ["@", "%", "$"]):
#             explanation.append("Suspicious characters detected")
#         if pred_label == 'bad' and not explanation:
#             explanation.append("Predicted phishing based on model patterns")
    
#     return render_template("home.html", predict=predict, explanation=explanation, url_value=url_input)

# @app.route("/team")
# def team():
#     return render_template("team.html")

# @app.route("/details")
# def details():
#     return render_template("details.html")

# if __name__ == "__main__":
#     app.run(debug=True)









from flask import Flask, render_template, request
import pickle
import numpy as np
import re
from gensim.models import Word2Vec
from urllib.parse import urlparse

app = Flask(__name__)

# ============================================================
# Load Trained Artefacts
# ============================================================
xgb_model = pickle.load(open('phishing_xgb.pkl', 'rb'))
scaler     = pickle.load(open('scaler.pkl', 'rb'))
le         = pickle.load(open('label_encoder.pkl', 'rb'))
w2v_model  = Word2Vec.load('w2v_model.bin')
THRESHOLD  = pickle.load(open('threshold.pkl', 'rb'))

# Derive the numeric label for "bad" from the encoder
# (matches how bad_label was computed during training)
label_map = dict(zip(le.classes_, le.transform(le.classes_)))
BAD_LABEL  = label_map['bad']


# ============================================================
# Constants — must mirror notebook exactly
# ============================================================
SUSPICIOUS_TLDS = {'ru', 'cn', 'tk', 'ml', 'xyz', 'info', 'top', 'gq', 'ga', 'cf', 'pw'}

TRUSTED_DOMAINS = {
    # Major tech & services
    'google.com', 'apple.com', 'amazon.com', 'facebook.com',
    'microsoft.com', 'github.com', 'wikipedia.org', 'linkedin.com',
    'twitter.com', 'youtube.com', 'netflix.com', 'reddit.com',
    'stackoverflow.com', 'nytimes.com', 'bbc.com',
    # Finance & payments
    'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com',
    # Developer tools
    'rawgit.com', 'jsdelivr.net', 'cloudflare.com', 'npmjs.com',
    'pypi.org', 'anaconda.com', 'heroku.com', 'vercel.app',
    # Email providers
    'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
    # Shopping
    'ebay.com', 'walmart.com', 'flipkart.com', 'shopify.com',
    # Indian trusted domains
    'irctc.co.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
}


# ============================================================
# Preprocessing Helpers — identical to notebook
# ============================================================
def normalize_url(url: str) -> str:
    """Prepend http:// if no scheme present (fixes urlparse edge case)."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_trusted_domain(url: str) -> bool:
    """Return True if the URL's root domain is in the trusted list.
    Matches subdomains too: accounts.google.com → google.com ✓
    """
    netloc = urlparse(url).netloc.lower()
    parts  = netloc.replace("www.", "").split(".")
    root   = ".".join(parts[-2:]) if len(parts) >= 2 else netloc
    return root in TRUSTED_DOMAINS


def extract_features(url: str) -> list:
    """
    10 structural features — must stay in sync with the notebook.
    Returns a zero-vector on any parsing error (safe fallback).
    """
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        tld    = netloc.split('.')[-1] if '.' in netloc else ''

        is_http           = 1 if parsed.scheme == "http" else 0
        url_length        = len(url)
        subdomain_count   = max(len(netloc.split('.')) - 2, 0)
        dot_count         = url.count('.')
        has_ip            = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc) else 0
        suspicious_chars  = sum(c in url for c in ['@', '%', '-', '?', '=', '~'])
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        has_double_slash  = 1 if '//' in url[8:] else 0

        prob    = [float(url.count(c)) / len(url) for c in set(url)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)

        # Extract root domain so subdomains (accounts.google.com,
        # mail.google.com, etc.) correctly match the trusted list
        netloc_parts = netloc.replace("www.", "").split(".")
        root_domain  = ".".join(netloc_parts[-2:]) if len(netloc_parts) >= 2 else netloc
        is_trusted   = 1 if root_domain in TRUSTED_DOMAINS else 0

        return [
            is_http, url_length, subdomain_count, dot_count,
            has_ip, suspicious_chars, has_suspicious_tld,
            has_double_slash, entropy, is_trusted,
        ]

    except Exception:
        return [0] * 10


def tokenize_url(url: str) -> list:
    """Split URL into lowercase tokens, drop empty strings."""
    tokens = re.split(r'\W+', url.lower())
    return [t for t in tokens if t]


def embed_tokens(tokens: list) -> np.ndarray:
    """Average Word2Vec vectors; zero-vector if no known tokens."""
    known = [t for t in tokens if t in w2v_model.wv]
    if not known:
        return np.zeros(w2v_model.vector_size)
    return np.mean([w2v_model.wv[t] for t in known], axis=0)


def predict_url(url: str) -> dict:
    """
    Full inference pipeline — mirrors notebook Section 16.

    Returns:
        label      : 'bad' or 'good'
        confidence : probability of being BAD (0–100 %)
        prob       : raw probability float (0–1)
        risk       : 'HIGH', 'MEDIUM', or 'LOW'
    """
    struct = np.array(extract_features(url)).reshape(1, -1)
    embed  = embed_tokens(tokenize_url(url)).reshape(1, -1)

    X        = np.hstack([struct * 5, embed])   # same weighting as training
    X_scaled = scaler.transform(X)

    # Column 0 = P(bad) — must match the column used during threshold tuning
    prob_bad = xgb_model.predict_proba(X_scaled)[0][0]
    label    = 'bad' if prob_bad >= THRESHOLD else 'good'

    if prob_bad >= 0.75:
        risk = 'HIGH'
    elif prob_bad >= THRESHOLD:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    return {
        'label':      label,
        'confidence': round(prob_bad * 100, 2),
        'prob':       float(prob_bad),
        'risk':       risk,
    }


# ============================================================
# Explanation Builder
# ============================================================
def build_explanation(url: str, result: dict) -> list:
    """Generate human-readable reasons for the prediction."""
    reasons = []
    parsed  = urlparse(url)

    if parsed.scheme == "http":
        reasons.append("Uses HTTP instead of HTTPS")
    if len(url) > 75:
        reasons.append("URL is unusually long")
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed.netloc):
        reasons.append("IP address used instead of a domain name")
    if any(c in url for c in ['@', '%', '~']):
        reasons.append("Suspicious characters detected (@, %, ~)")
    tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious top-level domain (.{tld})")
    if '//' in url[8:]:
        reasons.append("Double-slash redirect trick detected")
    if result['prob'] >= 0.75:
        reasons.append("Very high phishing probability from ML model")
    elif result['prob'] >= THRESHOLD:
        reasons.append("Elevated phishing probability from ML model")

    # Fallback so the list is never empty on a bad prediction
    if result['label'] == 'bad' and not reasons:
        reasons.append("Suspicious structural patterns detected in URL")

    return reasons


# ============================================================
# Flask Routes
# ============================================================
@app.route("/", methods=['GET', 'POST'])
def home():
    predict     = None
    explanation = []
    url_input   = ""
    risk_level  = None

    if request.method == "POST":
        url_input = request.form.get('url', '').strip()

        # --- Empty input guard ---
        if not url_input:
            predict = "Please enter a valid URL."
            return render_template(
                "home.html",
                predict=predict, explanation=explanation,
                url_value=url_input, risk=risk_level,
            )

        # --- Normalise (add scheme if missing) ---
        url_input = normalize_url(url_input)

        # --- Trusted domain shortcut ---
        if is_trusted_domain(url_input):
            predict     = "✅ This site is Safe (Trusted Domain)"
            explanation = ["Recognised as a globally trusted domain"]
            risk_level  = "LOW"
            return render_template(
                "home.html",
                predict=predict, explanation=explanation,
                url_value=url_input, risk=risk_level,
            )

        # --- ML Prediction ---
        try:
            result     = predict_url(url_input)
            risk_level = result['risk']
            explanation = build_explanation(url_input, result)

            # Secondary safety net: if model says bad but confidence is
            # borderline (< 80%) and URL has no strong phishing signals
            # (no IP, no suspicious TLD, uses HTTPS), downgrade to safe.
            parsed_check = urlparse(url_input)
            tld_check    = parsed_check.netloc.split(".")[-1]
            has_ip       = bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed_check.netloc))
            sus_tld      = tld_check in SUSPICIOUS_TLDS
            is_https     = url_input.startswith("https://")

            if (result['label'] == 'bad'
                    and result['prob'] < 0.85
                    and not has_ip
                    and not sus_tld):
                risk_level  = "LOW"
                safe_conf   = round((1 - result['prob']) * 100, 1)
                predict     = f"✅ This site appears Safe — {safe_conf:.1f}% confidence"
                explanation = ["No strong phishing signals detected (no IP, no suspicious TLD)"]
            elif result['label'] == 'bad':
                predict = f"🚨 Phishing Detected — {result['confidence']:.1f}% confidence ({risk_level} risk)"
            else:
                safe_conf = round((1 - result['prob']) * 100, 1)
                predict   = f"✅ This site appears Safe — {safe_conf:.1f}% confidence"

        except Exception as e:
            print(f"[ERROR] Prediction failed for '{url_input}': {e}")
            predict     = "⚠️ Prediction error. Please try again."
            explanation = ["An internal error occurred during analysis."]

    return render_template(
        "home.html",
        predict=predict, explanation=explanation,
        url_value=url_input, risk=risk_level,
    )


@app.route("/team")
def team():
    return render_template("team.html")


@app.route("/details")
def details():
    return render_template("details.html")


if __name__ == "__main__":
    app.run(debug=True)