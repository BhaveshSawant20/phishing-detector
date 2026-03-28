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









# from flask import Flask, render_template, request
# import pickle
# import numpy as np
# import re
# import os
# import requests
# from gensim.models import Word2Vec
# from urllib.parse import urlparse

# app = Flask(__name__)

# # ============================================================
# # 🔥 DOWNLOAD MODEL (CRITICAL FIX)
# # ============================================================
# def download_file(url, filename):
#     if not os.path.exists(filename):
#         print(f"Downloading {filename}...")
#         response = requests.get(url, stream=True)

#         if response.status_code != 200:
#             raise Exception("Failed to download model")

#         with open(filename, "wb") as f:
#             for chunk in response.iter_content(1024):
#                 if chunk:
#                     f.write(chunk)

# # 🔥 Your Google Drive Direct Link
# W2V_URL = "https://drive.google.com/uc?export=download&id=1HUWeXgtQ0Ds8VxxKlpgTEyu4gLH-vC6h"

# download_file(W2V_URL, "w2v_model.bin")


# # ============================================================
# # Load Trained Artefacts
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
# SUSPICIOUS_TLDS = {'ru', 'cn', 'tk', 'ml', 'xyz', 'info', 'top', 'gq', 'ga', 'cf', 'pw'}

# TRUSTED_DOMAINS = {
#     'google.com', 'apple.com', 'amazon.com', 'facebook.com',
#     'microsoft.com', 'github.com', 'wikipedia.org', 'linkedin.com',
#     'twitter.com', 'youtube.com', 'netflix.com', 'reddit.com',
#     'stackoverflow.com', 'nytimes.com', 'bbc.com',
#     'paypal.com', 'stripe.com', 'chase.com', 'bankofamerica.com',
#     'rawgit.com', 'jsdelivr.net', 'cloudflare.com', 'npmjs.com',
#     'pypi.org', 'anaconda.com', 'heroku.com', 'vercel.app',
#     'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
#     'ebay.com', 'walmart.com', 'flipkart.com', 'shopify.com',
#     'irctc.co.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
# }


# # ============================================================
# # Helpers
# # ============================================================
# def normalize_url(url: str) -> str:
#     url = url.strip()
#     if not url.startswith(("http://", "https://")):
#         url = "http://" + url
#     return url


# def is_trusted_domain(url: str) -> bool:
#     netloc = urlparse(url).netloc.lower()
#     parts  = netloc.replace("www.", "").split(".")
#     root   = ".".join(parts[-2:]) if len(parts) >= 2 else netloc
#     return root in TRUSTED_DOMAINS


# def extract_features(url: str) -> list:
#     try:
#         parsed = urlparse(url)
#         netloc = parsed.netloc.lower()
#         tld    = netloc.split('.')[-1] if '.' in netloc else ''

#         is_http = 1 if parsed.scheme == "http" else 0
#         url_length = len(url)
#         subdomain_count = max(len(netloc.split('.')) - 2, 0)
#         dot_count = url.count('.')
#         has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc) else 0
#         suspicious_chars = sum(c in url for c in ['@', '%', '-', '?', '=', '~'])
#         has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
#         has_double_slash = 1 if '//' in url[8:] else 0

#         prob = [float(url.count(c)) / len(url) for c in set(url)]
#         entropy = -sum(p * np.log2(p) for p in prob if p > 0)

#         netloc_parts = netloc.replace("www.", "").split(".")
#         root_domain = ".".join(netloc_parts[-2:])
#         is_trusted = 1 if root_domain in TRUSTED_DOMAINS else 0

#         return [
#             is_http, url_length, subdomain_count, dot_count,
#             has_ip, suspicious_chars, has_suspicious_tld,
#             has_double_slash, entropy, is_trusted,
#         ]
#     except:
#         return [0]*10


# def tokenize_url(url: str):
#     return [t for t in re.split(r'\W+', url.lower()) if t]


# def embed_tokens(tokens):
#     known = [t for t in tokens if t in w2v_model.wv]
#     if not known:
#         return np.zeros(w2v_model.vector_size)
#     return np.mean([w2v_model.wv[t] for t in known], axis=0)


# def predict_url(url: str):
#     struct = np.array(extract_features(url)).reshape(1, -1)
#     embed  = embed_tokens(tokenize_url(url)).reshape(1, -1)

#     X = np.hstack([struct * 5, embed])
#     X_scaled = scaler.transform(X)

#     prob_bad = xgb_model.predict_proba(X_scaled)[0][0]
#     label = 'bad' if prob_bad >= THRESHOLD else 'good'

#     risk = "HIGH" if prob_bad >= 0.75 else "MEDIUM" if prob_bad >= THRESHOLD else "LOW"

#     return label, prob_bad, risk


# # ============================================================
# # Routes
# # ============================================================
# @app.route("/", methods=['GET', 'POST'])
# def home():
#     predict = None
#     explanation = []
#     url_input = ""
#     risk = None

#     if request.method == "POST":
#         url_input = request.form.get('url', '').strip()

#         if not url_input:
#             predict = "Enter a valid URL"
#             return render_template("home.html", predict=predict)

#         url_input = normalize_url(url_input)

#         if is_trusted_domain(url_input):
#             return render_template("home.html",
#                                    predict="✅ Safe (Trusted Domain)",
#                                    risk="LOW")

#         try:
#             label, prob, risk = predict_url(url_input)

#             if label == 'bad':
#                 predict = f"🚨 Phishing ({prob*100:.2f}%)"
#             else:
#                 predict = f"✅ Safe ({(1-prob)*100:.2f}%)"

#         except Exception as e:
#             print(e)
#             predict = "Prediction Error"

#     return render_template("home.html",
#                            predict=predict,
#                            url_value=url_input,
#                            risk=risk)


# @app.route("/team")
# def team():
#     return render_template("team.html")


# @app.route("/details")
# def details():
#     return render_template("details.html")


# # ============================================================
# # Run (DEPLOYMENT READY)
# # ============================================================
# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 5000))
#     app.run(host="0.0.0.0", port=port)













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
SUSPICIOUS_TLDS = {'ru','cn','tk','ml','xyz','info','top','gq','ga','cf','pw'}

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

        is_http = 1 if parsed.scheme=="http" else 0
        url_length = len(url)
        subdomain_count = max(len(netloc.split('.'))-2,0)
        dot_count = url.count('.')
        has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', netloc) else 0
        suspicious_chars = sum(c in url for c in ['@','%','-','?','=','~'])
        has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
        has_double_slash = 1 if '//' in url[8:] else 0

        prob = [float(url.count(c))/len(url) for c in set(url)]
        entropy = -sum(p*np.log2(p) for p in prob if p>0)

        netloc_parts = netloc.replace("www.","").split(".")
        root_domain  = ".".join(netloc_parts[-2:]) if len(netloc_parts)>=2 else netloc
        is_trusted = 1 if root_domain in TRUSTED_DOMAINS else 0

        return [
            is_http,url_length,subdomain_count,dot_count,
            has_ip,suspicious_chars,has_suspicious_tld,
            has_double_slash,entropy,is_trusted
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
    struct = np.array(extract_features(url)).reshape(1,-1)
    embed  = embed_tokens(tokenize_url(url)).reshape(1,-1)

    X = np.hstack([struct*5, embed])
    X_scaled = scaler.transform(X)

    prob_bad = xgb_model.predict_proba(X_scaled)[0][0]
    label = 'bad' if prob_bad >= THRESHOLD else 'good'

    if prob_bad >= 0.75:
        risk = 'HIGH'
    elif prob_bad >= THRESHOLD:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    return {
        'label': label,
        'confidence': round(prob_bad*100,2),
        'prob': float(prob_bad),
        'risk': risk
    }

def build_explanation(url, result):
    reasons = []
    parsed = urlparse(url)

    if parsed.scheme=="http":
        reasons.append("Uses HTTP instead of HTTPS")
    if len(url)>75:
        reasons.append("URL is unusually long")
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', parsed.netloc):
        reasons.append("IP address used instead of domain")
    if any(c in url for c in ['@','%','~']):
        reasons.append("Suspicious characters detected")
    tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious TLD (.{tld})")
    if '//' in url[8:]:
        reasons.append("Double slash redirect detected")

    return reasons

# ============================================================
# MAIN ROUTE (FIXED PROPERLY)
# ============================================================
@app.route("/", methods=["GET","POST"])
def home():

    # ================= POST =================
    if request.method == "POST":
        url_input = request.form.get("url","").strip()

        if not url_input:
            session["result"] = {
                "predict": "⚠️ Please enter a valid URL",
                "risk": None,
                "explanation": [],
                "url": ""
            }
            return redirect(url_for("home"))

        url_input = normalize_url(url_input)

        # Trusted
        if is_trusted_domain(url_input):
            session["result"] = {
                "predict": "✅ Safe (Trusted Domain)",
                "risk": "LOW",
                "explanation": ["Recognised trusted domain"],
                "url": url_input   # ✅ KEEP URL
            }
            return redirect(url_for("home"))

        try:
            result = predict_url(url_input)
            explanation = build_explanation(url_input, result)

            if result['label']=="bad":
                predict = f"🚨 Phishing — {result['confidence']}% ({result['risk']})"
            else:
                safe_conf = round((1-result['prob'])*100,1)
                predict = f"✅ Safe — {safe_conf}% confidence"

            session["result"] = {
                "predict": predict,
                "risk": result['risk'],
                "explanation": explanation,
                "url": url_input   # ✅ KEEP URL
            }

        except Exception as e:
            session["result"] = {
                "predict": "⚠️ Prediction error",
                "risk": None,
                "explanation": [str(e)],
                "url": url_input
            }

        return redirect(url_for("home"))

    # ================= GET =================
    result = session.pop("result", None)

    return render_template(
        "home.html",
        url_value=result["url"] if result else "",   # 🔥 FIXED
        predict=result["predict"] if result else None,
        risk=result["risk"] if result else None,
        explanation=result["explanation"] if result else None
    )

# ============================================================
# Other Routes
# ============================================================
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