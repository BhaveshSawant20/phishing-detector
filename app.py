from flask import Flask, render_template, request, redirect, url_for, session
import pickle
import numpy as np
import re
from gensim.models import Word2Vec
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = "super_secret_key_123"

# ============================================================
# Load Models
# ============================================================
xgb_model = pickle.load(open('phishing_xgb.pkl', 'rb'))
scaler     = pickle.load(open('scaler.pkl', 'rb'))
le         = pickle.load(open('label_encoder.pkl', 'rb'))
w2v_model  = Word2Vec.load('w2v_model.bin')
THRESHOLD  = pickle.load(open('threshold.pkl', 'rb'))

label_map = dict(zip(le.classes_, le.transform(le.classes_)))
BAD_LABEL  = label_map['bad']

# ============================================================
# Constants
# ============================================================
SUSPICIOUS_TLDS = {
    # Classic phishing TLDs
    'ru','cn','tk','ml','xyz','info','top','gq','ga','cf','pw',
    # Commonly abused newer TLDs
    'live','to','sh','gmbh','click','link','online','site',
    'fun','icu','club','vip','win','bid','loan','work',
    'download','stream','watch','movies','tv','cam',
    'zip','mov','wav','review','trade','party',
}

TRUSTED_DOMAINS = {
    'google.com','apple.com','amazon.com','facebook.com',
    'microsoft.com','github.com','wikipedia.org','linkedin.com',
    'twitter.com','youtube.com','netflix.com','reddit.com',
    'stackoverflow.com','nytimes.com','bbc.com',
    'paypal.com','stripe.com','chase.com','bankofamerica.com',
    'rawgit.com','jsdelivr.net','cloudflare.com','npmjs.com',
    'pypi.org','anaconda.com','heroku.com','vercel.app',
    'gmail.com','outlook.com','yahoo.com','protonmail.com',
    'ebay.com','walmart.com','flipkart.com','shopify.com',
    'irctc.co.in','sbi.co.in','hdfcbank.com','icicibank.com'
}

# ============================================================
# Helpers
# ============================================================
def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    return url

def is_trusted_domain(url):
    netloc = urlparse(url).netloc.lower()
    parts  = netloc.replace("www.","").split(".")
    root   = ".".join(parts[-2:]) if len(parts)>=2 else netloc
    return root in TRUSTED_DOMAINS

def extract_features(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        tld    = netloc.split('.')[-1] if '.' in netloc else ''

        is_http          = 1 if parsed.scheme=="http" else 0
        url_length       = len(url)
        subdomain_count  = max(len(netloc.split('.'))-2, 0)
        dot_count        = url.count('.')
        has_ip           = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc) else 0
        suspicious_chars = sum(c in url for c in ['@','%','-','?','=','~'])
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        has_double_slash = 1 if '//' in url[8:] else 0

        prob    = [float(url.count(c))/len(url) for c in set(url)]
        entropy = -sum(p*np.log2(p) for p in prob if p>0)

        netloc_parts = netloc.replace("www.","").split(".")
        root_domain  = ".".join(netloc_parts[-2:]) if len(netloc_parts)>=2 else netloc
        is_trusted   = 1 if root_domain in TRUSTED_DOMAINS else 0

        return [
            is_http, url_length, subdomain_count, dot_count,
            has_ip, suspicious_chars, has_suspicious_tld,
            has_double_slash, entropy, is_trusted
        ]
    except:
        return [0]*10

def tokenize_url(url):
    tokens = re.split(r'\W+', url.lower())
    return [t for t in tokens if t]

def embed_tokens(tokens):
    known = [t for t in tokens if t in w2v_model.wv]
    if not known:
        return np.zeros(w2v_model.vector_size)
    return np.mean([w2v_model.wv[t] for t in known], axis=0)

def predict_url(url):
    struct   = np.array(extract_features(url)).reshape(1,-1)
    embed    = embed_tokens(tokenize_url(url)).reshape(1,-1)
    X        = np.hstack([struct*5, embed])
    X_scaled = scaler.transform(X)

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
        'confidence': round(prob_bad*100, 2),
        'prob':       float(prob_bad),
        'risk':       risk
    }

def build_explanation(url, result):
    """
    Build a comprehensive list of human-readable reasons.
    Always returns at least one reason for any prediction.
    """
    reasons = []
    parsed  = urlparse(url)
    netloc  = parsed.netloc.lower()
    tld     = netloc.split('.')[-1] if '.' in netloc else ''
    path    = parsed.path.lower()

    # --- HTTP check ---
    if parsed.scheme == "http":
        reasons.append("Uses HTTP instead of HTTPS (connection is not encrypted)")

    # --- URL length ---
    if len(url) > 100:
        reasons.append(f"URL is very long ({len(url)} characters) — often used to hide true destination")
    elif len(url) > 75:
        reasons.append(f"URL is unusually long ({len(url)} characters)")

    # --- IP address ---
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc):
        reasons.append("IP address used instead of a domain name — websites rarely do this legitimately")

    # --- Suspicious characters ---
    found_chars = [c for c in ['@', '%', '~', '!', '$'] if c in url]
    if found_chars:
        reasons.append(f"Suspicious characters found in URL: {', '.join(found_chars)}")

    # --- Suspicious TLD ---
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Uncommon or suspicious top-level domain (.{tld}) — frequently used in phishing and piracy sites")

    # --- Double slash redirect ---
    if '//' in url[8:]:
        reasons.append("Double-slash redirect trick detected in URL path")

    # --- Excessive subdomains ---
    subdomain_count = max(len(netloc.replace('www.', '').split('.')) - 2, 0)
    if subdomain_count >= 3:
        reasons.append(f"Excessive subdomains ({subdomain_count}) — common in domain spoofing attacks")
    elif url.count('.') > 4:
        reasons.append("Excessive dots in URL — common in spoofed or obfuscated domains")

    # --- Phishing keywords ---
    phishing_keywords = [
        'login','verify','secure','update','confirm','account',
        'banking','signin','password','credential','suspend',
        'unlock','validate','billing','paypal','apple','microsoft'
    ]
    found_keywords = [w for w in phishing_keywords if w in url.lower()]
    if found_keywords:
        reasons.append(f"URL contains phishing-associated keywords: {', '.join(found_keywords)}")

    # --- Streaming / piracy keywords ---
    piracy_keywords = [
        'movies','watch','stream','flix','anime','torrent',
        'download','free','hd','series','episode','vega','flixer'
    ]
    found_piracy = [w for w in piracy_keywords if w in url.lower()]
    if found_piracy:
        reasons.append(f"URL contains streaming/piracy-associated keywords: {', '.join(found_piracy)}")

    # --- Hyphenated domain ---
    domain_part = netloc.replace('www.', '').split('.')[0]
    if domain_part.count('-') >= 2:
        reasons.append("Domain contains multiple hyphens — commonly used to mimic legitimate sites")
    elif '-' in domain_part:
        reasons.append("Hyphenated domain name — often used in phishing to imitate real brands")

    # --- Sensitive path over HTTP ---
    sensitive_paths = ['login','signin','account','payment','checkout','banking','verify']
    if parsed.scheme == 'http' and any(s in path for s in sensitive_paths):
        reasons.append("Sensitive page (login/payment) served over insecure HTTP")

    # --- Long domain name ---
    if len(domain_part) > 20:
        reasons.append(f"Unusually long domain name ({len(domain_part)} chars) — may be randomly generated")

    # --- ML confidence ---
    if result['prob'] >= 0.90:
        reasons.append(f"Very high phishing probability from ML model ({result['confidence']}%)")
    elif result['prob'] >= 0.75:
        reasons.append(f"High phishing probability from ML model ({result['confidence']}%)")
    elif result['prob'] >= THRESHOLD:
        reasons.append(f"Elevated phishing probability from ML model ({result['confidence']}%)")

    # --- Safe signals (show for good results) ---
    if result['label'] == 'good':
        if parsed.scheme == 'https':
            reasons.append("Uses HTTPS — connection is encrypted and secure")
        if not re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc):
            reasons.append("Uses a proper domain name, not a raw IP address")
        if tld in ['com','org','net','gov','edu','in','co.in']:
            reasons.append(f"Legitimate top-level domain (.{tld})")
        if not found_keywords and not found_piracy:
            reasons.append("No phishing-associated keywords detected in the URL")
        if result['prob'] < 0.20:
            reasons.append(f"Very low phishing probability from ML model ({result['confidence']}%)")

    # --- Fallback ---
    if result['label'] == 'bad' and not reasons:
        reasons.append("Suspicious structural patterns detected in the URL")

    return reasons

# ============================================================
# Routes
# ============================================================
@app.route("/", methods=["GET","POST"])
def home():

    # ── POST ──────────────────────────────────────────────
    if request.method == "POST":
        url_input = request.form.get("url","").strip()

        if not url_input:
            session["result"] = {
                "predict": "⚠️ Please enter a valid URL",
                "risk": None, "explanation": [], "url": ""
            }
            return redirect(url_for("home"))

        url_input = normalize_url(url_input)

        # Trusted domain shortcut
        if is_trusted_domain(url_input):
            parsed_t = urlparse(url_input)
            tld_t    = parsed_t.netloc.split('.')[-1] if '.' in parsed_t.netloc else ''
            trust_reasons = ["Recognised as a globally trusted domain"]

            if url_input.startswith("https://"):
                trust_reasons.append("Uses HTTPS — connection is encrypted and secure")
            if not re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed_t.netloc):
                trust_reasons.append("Uses a proper domain name, not a raw IP address")
            if tld_t in ['com', 'org', 'net', 'gov', 'edu', 'in']:
                trust_reasons.append(f"Legitimate top-level domain (.{tld_t})")
            if url_input.count('.') <= 3:
                trust_reasons.append("Clean URL structure with no excessive subdomains")
            if not any(c in url_input for c in ['@', '%', '~']):
                trust_reasons.append("No suspicious characters found in the URL")

            session["result"] = {
                "predict":     "✅ Safe (Trusted Domain)",
                "risk":        "LOW",
                "explanation": trust_reasons,
                "url":         url_input
            }
            return redirect(url_for("home"))

        # ML prediction
        try:
            result      = predict_url(url_input)
            explanation = build_explanation(url_input, result)

            parsed_check = urlparse(url_input)
            tld_check    = parsed_check.netloc.split(".")[-1]
            has_ip       = bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed_check.netloc))
            sus_tld      = tld_check in SUSPICIOUS_TLDS

            # Safety net: borderline bad prediction with no strong signals → safe
            if result['label'] == 'bad' and result['prob'] < 0.85 and not has_ip and not sus_tld:
                safe_conf   = round((1 - result['prob']) * 100, 1)
                predict     = f"✅ Safe — {safe_conf}% confidence"
                risk        = "LOW"
                explanation = ["No strong phishing signals detected (no IP, no suspicious TLD)"]
            elif result['label'] == 'bad':
                predict = f"🚨 Phishing — {result['confidence']}% ({result['risk']})"
                risk    = result['risk']
            else:
                safe_conf = round((1 - result['prob']) * 100, 1)
                predict   = f"✅ Safe — {safe_conf}% confidence"
                risk      = result['risk']

            session["result"] = {
                "predict":     predict,
                "risk":        risk,
                "explanation": explanation,
                "url":         url_input
            }

        except Exception as e:
            session["result"] = {
                "predict":     "⚠️ Prediction error. Please try again.",
                "risk":        None,
                "explanation": ["An internal error occurred during analysis."],
                "url":         url_input
            }
            print(f"[ERROR] {e}")

        return redirect(url_for("home"))

    # ── GET ───────────────────────────────────────────────
    result = session.pop("result", None)

    return render_template(
        "home.html",
        url_value=  result["url"]         if result else "",
        predict=    result["predict"]      if result else None,
        risk=       result["risk"]         if result else None,
        explanation=result["explanation"]  if result else None,
    )

@app.route("/team")
def team():
    return render_template("team.html")

@app.route("/details")
def details():
    return render_template("details.html")

@app.route("/ping")
def ping():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860, debug=False)













# from flask import Flask, render_template, request, redirect, url_for, session
# import pickle
# import numpy as np
# import re
# from gensim.models import Word2Vec
# from urllib.parse import urlparse

# app = Flask(__name__)
# app.secret_key = "super_secret_key_123"

# # ============================================================
# # Load Models
# # ============================================================
# xgb_model = pickle.load(open('phishing_xgb.pkl', 'rb'))
# scaler     = pickle.load(open('scaler.pkl', 'rb'))
# le         = pickle.load(open('label_encoder.pkl', 'rb'))
# w2v_model  = Word2Vec.load('w2v_model.bin')
# THRESHOLD  = pickle.load(open('threshold.pkl', 'rb'))

# label_map = dict(zip(le.classes_, le.transform(le.classes_)))
# BAD_LABEL  = label_map['bad']

# # ============================================================
# # Constants
# # ============================================================
# SUSPICIOUS_TLDS = {'ru','cn','tk','ml','xyz','info','top','gq','ga','cf','pw'}

# TRUSTED_DOMAINS = {
#     'google.com','apple.com','amazon.com','facebook.com',
#     'microsoft.com','github.com','wikipedia.org','linkedin.com',
#     'twitter.com','youtube.com','netflix.com','reddit.com',
#     'stackoverflow.com','nytimes.com','bbc.com',
#     'paypal.com','stripe.com','chase.com','bankofamerica.com',
#     'rawgit.com','jsdelivr.net','cloudflare.com','npmjs.com',
#     'pypi.org','anaconda.com','heroku.com','vercel.app',
#     'gmail.com','outlook.com','yahoo.com','protonmail.com',
#     'ebay.com','walmart.com','flipkart.com','shopify.com',
#     'irctc.co.in','sbi.co.in','hdfcbank.com','icicibank.com'
# }

# # ============================================================
# # Helpers
# # ============================================================
# def normalize_url(url):
#     url = url.strip()
#     if not url.startswith(("http://","https://")):
#         url = "http://" + url
#     return url

# def is_trusted_domain(url):
#     netloc = urlparse(url).netloc.lower()
#     parts  = netloc.replace("www.","").split(".")
#     root   = ".".join(parts[-2:]) if len(parts)>=2 else netloc
#     return root in TRUSTED_DOMAINS

# def extract_features(url):
#     try:
#         parsed = urlparse(url)
#         netloc = parsed.netloc.lower()
#         tld    = netloc.split('.')[-1] if '.' in netloc else ''

#         is_http          = 1 if parsed.scheme=="http" else 0
#         url_length       = len(url)
#         subdomain_count  = max(len(netloc.split('.'))-2, 0)
#         dot_count        = url.count('.')
#         has_ip           = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc) else 0
#         suspicious_chars = sum(c in url for c in ['@','%','-','?','=','~'])
#         has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
#         has_double_slash = 1 if '//' in url[8:] else 0

#         prob    = [float(url.count(c))/len(url) for c in set(url)]
#         entropy = -sum(p*np.log2(p) for p in prob if p>0)

#         netloc_parts = netloc.replace("www.","").split(".")
#         root_domain  = ".".join(netloc_parts[-2:]) if len(netloc_parts)>=2 else netloc
#         is_trusted   = 1 if root_domain in TRUSTED_DOMAINS else 0

#         return [
#             is_http, url_length, subdomain_count, dot_count,
#             has_ip, suspicious_chars, has_suspicious_tld,
#             has_double_slash, entropy, is_trusted
#         ]
#     except:
#         return [0]*10

# def tokenize_url(url):
#     tokens = re.split(r'\W+', url.lower())
#     return [t for t in tokens if t]

# def embed_tokens(tokens):
#     known = [t for t in tokens if t in w2v_model.wv]
#     if not known:
#         return np.zeros(w2v_model.vector_size)
#     return np.mean([w2v_model.wv[t] for t in known], axis=0)

# def predict_url(url):
#     struct   = np.array(extract_features(url)).reshape(1,-1)
#     embed    = embed_tokens(tokenize_url(url)).reshape(1,-1)
#     X        = np.hstack([struct*5, embed])
#     X_scaled = scaler.transform(X)

#     prob_bad = xgb_model.predict_proba(X_scaled)[0][0]
#     label    = 'bad' if prob_bad >= THRESHOLD else 'good'

#     if prob_bad >= 0.75:
#         risk = 'HIGH'
#     elif prob_bad >= THRESHOLD:
#         risk = 'MEDIUM'
#     else:
#         risk = 'LOW'

#     return {
#         'label':      label,
#         'confidence': round(prob_bad*100, 2),
#         'prob':       float(prob_bad),
#         'risk':       risk
#     }

# def build_explanation(url, result):
#     """
#     Build a list of human-readable reasons.
#     Always returns at least one reason for phishing predictions.
#     """
#     reasons = []
#     parsed  = urlparse(url)
#     tld     = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''

#     # Structural checks
#     if parsed.scheme == "http":
#         reasons.append("Uses HTTP instead of HTTPS (not secure)")
#     if len(url) > 75:
#         reasons.append("URL is unusually long")
#     if re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed.netloc):
#         reasons.append("IP address used instead of a domain name")
#     if any(c in url for c in ['@', '%', '~']):
#         reasons.append("Suspicious characters detected (@, %, ~)")
#     if tld in SUSPICIOUS_TLDS:
#         reasons.append(f"Suspicious top-level domain (.{tld})")
#     if '//' in url[8:]:
#         reasons.append("Double-slash redirect trick detected")
#     if url.count('.') > 4:
#         reasons.append("Excessive dots in URL (common in spoofed domains)")
#     if any(word in url.lower() for word in ['login','verify','secure','update','confirm','account','banking','signin']):
#         reasons.append("Contains keywords commonly used in phishing URLs")

#     # ML confidence reason
#     if result['prob'] >= 0.90:
#         reasons.append(f"Very high phishing probability from ML model ({result['confidence']}%)")
#     elif result['prob'] >= 0.75:
#         reasons.append(f"High phishing probability from ML model ({result['confidence']}%)")
#     elif result['prob'] >= THRESHOLD:
#         reasons.append(f"Elevated phishing probability from ML model ({result['confidence']}%)")

#     # Fallback — never show empty reasons for a phishing result
#     if result['label'] == 'bad' and not reasons:
#         reasons.append("Suspicious structural patterns detected in the URL")

#     return reasons

# # ============================================================
# # Routes
# # ============================================================
# @app.route("/", methods=["GET","POST"])
# def home():

#     # ── POST ──────────────────────────────────────────────
#     if request.method == "POST":
#         url_input = request.form.get("url","").strip()

#         if not url_input:
#             session["result"] = {
#                 "predict": "⚠️ Please enter a valid URL",
#                 "risk": None, "explanation": [], "url": ""
#             }
#             return redirect(url_for("home"))

#         url_input = normalize_url(url_input)

#         # Trusted domain shortcut
#         if is_trusted_domain(url_input):
#             parsed_t = urlparse(url_input)
#             tld_t    = parsed_t.netloc.split('.')[-1] if '.' in parsed_t.netloc else ''
#             trust_reasons = ["Recognised as a globally trusted domain"]

#             if url_input.startswith("https://"):
#                 trust_reasons.append("Uses HTTPS — connection is encrypted and secure")
#             if not re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed_t.netloc):
#                 trust_reasons.append("Uses a proper domain name, not a raw IP address")
#             if tld_t in ['com', 'org', 'net', 'gov', 'edu', 'in']:
#                 trust_reasons.append(f"Legitimate top-level domain (.{tld_t})")
#             if url_input.count('.') <= 3:
#                 trust_reasons.append("Clean URL structure with no excessive subdomains")
#             if not any(c in url_input for c in ['@', '%', '~']):
#                 trust_reasons.append("No suspicious characters found in the URL")

#             session["result"] = {
#                 "predict":     "✅ Safe (Trusted Domain)",
#                 "risk":        "LOW",
#                 "explanation": trust_reasons,
#                 "url":         url_input
#             }
#             return redirect(url_for("home"))

#         # ML prediction
#         try:
#             result      = predict_url(url_input)
#             explanation = build_explanation(url_input, result)

#             parsed_check = urlparse(url_input)
#             tld_check    = parsed_check.netloc.split(".")[-1]
#             has_ip       = bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed_check.netloc))
#             sus_tld      = tld_check in SUSPICIOUS_TLDS

#             # Safety net: borderline bad prediction with no strong signals → safe
#             if result['label'] == 'bad' and result['prob'] < 0.85 and not has_ip and not sus_tld:
#                 safe_conf = round((1 - result['prob']) * 100, 1)
#                 predict   = f"✅ Safe — {safe_conf}% confidence"
#                 risk      = "LOW"
#                 explanation = ["No strong phishing signals detected (no IP, no suspicious TLD)"]
#             elif result['label'] == 'bad':
#                 predict = f"🚨 Phishing — {result['confidence']}% ({result['risk']})"
#                 risk    = result['risk']
#             else:
#                 safe_conf = round((1 - result['prob']) * 100, 1)
#                 predict   = f"✅ Safe — {safe_conf}% confidence"
#                 risk      = result['risk']

#             session["result"] = {
#                 "predict":     predict,
#                 "risk":        risk,
#                 "explanation": explanation,
#                 "url":         url_input
#             }

#         except Exception as e:
#             session["result"] = {
#                 "predict":     "⚠️ Prediction error. Please try again.",
#                 "risk":        None,
#                 "explanation": ["An internal error occurred during analysis."],
#                 "url":         url_input
#             }
#             print(f"[ERROR] {e}")

#         return redirect(url_for("home"))

#     # ── GET ───────────────────────────────────────────────
#     result = session.pop("result", None)

#     return render_template(
#         "home.html",
#         url_value=  result["url"]         if result else "",
#         predict=    result["predict"]      if result else None,
#         risk=       result["risk"]         if result else None,
#         explanation=result["explanation"]  if result else None,
#     )

# @app.route("/team")
# def team():
#     return render_template("team.html")

# @app.route("/details")
# def details():
#     return render_template("details.html")

# @app.route("/ping")
# def ping():
#     return "ok"

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=7860, debug=False)