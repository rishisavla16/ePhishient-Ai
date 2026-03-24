import pandas as pd
import numpy as np
import re
import joblib
import math
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, roc_auc_score
from data_loader import DataLoader

class PhishingDetector:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            class_weight='balanced_subsample',
            min_samples_leaf=2,
            n_jobs=-1
        )
        self.feature_names = [
            'url_length', 'hostname_length', 'path_length', 'fd_length', 'tld_length',
            'count_dash', 'count_at', 'count_question', 'count_percent', 'count_dot',
            'count_equal', 'count_ampersand', 'count_underscore',
            'count_digits', 'count_alpha',
            'is_ip', 'short_url', 'https_token', 'sensitive_words', 'entropy',
            'subdomain_count', 'has_port', 'digit_ratio', 'special_char_ratio',
            'suspicious_tld', 'double_slash_path', 'query_param_count', 'hex_char_count'
        ]

    @staticmethod
    def normalize_url(url):
        """Normalize URL text for consistent feature extraction and deduplication."""
        if pd.isna(url):
            return ""

        url = str(url).strip()
        if not url:
            return ""

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        hostname = parsed.netloc.lower().strip()

        # Drop leading www for more stable domain grouping.
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        path = parsed.path or '/'
        query = f"?{parsed.query}" if parsed.query else ''
        fragment = f"#{parsed.fragment}" if parsed.fragment else ''
        return f"{parsed.scheme.lower()}://{hostname}{path}{query}{fragment}"

    @staticmethod
    def _domain_group(hostname):
        """Create a stable domain group key to reduce train/test leakage across same hosts."""
        host = (hostname or '').split(':')[0].lower()
        if host.startswith('www.'):
            host = host[4:]

        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host

    def get_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_features(self, url):
        """
        Extracts comprehensive lexical features from a URL based on common phishing indicators.
        """
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Feature extraction logic
        features = {}
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        features['fd_length'] = len(path.split('/')[1]) if len(path.split('/')) > 1 else 0
        
        # TLD length (approximate)
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        features['tld_length'] = len(tld)
        
        # Character Counts
        features['count_dash'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_percent'] = url.count('%')
        features['count_dot'] = url.count('.')
        features['count_equal'] = url.count('=')
        features['count_ampersand'] = url.count('&')
        features['count_underscore'] = url.count('_')
        
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_alpha'] = sum(c.isalpha() for c in url)
        
        # Boolean / Binary Indicators
        features['is_ip'] = 1 if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'ow.ly', 'lc.chat']
        features['short_url'] = 1 if any(s in hostname for s in shorteners) else 0
        
        features['https_token'] = 1 if 'https' in parsed.scheme else 0
        
        sensitive = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'password']
        features['sensitive_words'] = sum(1 for w in sensitive if w in url.lower())
        
        # Entropy
        features['entropy'] = self.get_entropy(url)

        # Additional robust lexical signals
        host_no_port = hostname.split(':')[0]
        host_parts = host_no_port.split('.') if host_no_port else []
        features['subdomain_count'] = max(len(host_parts) - 2, 0)
        features['has_port'] = 1 if parsed.port else 0

        url_length = max(len(url), 1)
        special_chars = sum(not c.isalnum() for c in url)
        features['digit_ratio'] = features['count_digits'] / url_length
        features['special_char_ratio'] = special_chars / url_length

        suspicious_tlds = {'xyz', 'top', 'click', 'gq', 'cf', 'tk', 'work', 'support', 'zip', 'review'}
        features['suspicious_tld'] = 1 if tld.lower() in suspicious_tlds else 0
        features['double_slash_path'] = 1 if '//' in path else 0
        features['query_param_count'] = query.count('&') + (1 if query else 0)
        features['hex_char_count'] = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        
        # Return list in specific order
        return [features[key] for key in self.feature_names]

    def explain_prediction(self, features_list, prediction, url=None):
        """
        Simple rule-based explanation based on feature values.
        """
        reasons = []
        # Map list back to dict for easier logic
        feats = dict(zip(self.feature_names, features_list))

        if prediction == 1: # Malicious
            if feats.get('is_ip', 0) == 1:
                reasons.append("Hostname is an IP address (Indicator #9).")
            if feats.get('short_url', 0) == 1:
                reasons.append("Uses a URL shortening service (Indicator #8).")
            if feats.get('count_at', 0) > 0:
                reasons.append("Contains '@' symbol, often used for obfuscation (Indicator #48).")
            if feats.get('sensitive_words', 0) > 0:
                reasons.append("Contains sensitive keywords like 'login' or 'secure' (Indicator #16).")
            if feats.get('entropy', 0) > 4.5:
                reasons.append("High randomness (entropy) in URL structure (Indicator #37).")
            if feats.get('count_dash', 0) > 3:
                reasons.append("Excessive hyphens in domain (Indicator #13).")
            if feats.get('suspicious_tld', 0) == 1:
                reasons.append("Uses a commonly abused top-level domain.")
            if feats.get('hex_char_count', 0) > 3:
                reasons.append("Contains heavy URL encoding that may hide intent.")
            if feats.get('query_param_count', 0) > 4:
                reasons.append("Contains many query parameters often used for redirection or tracking abuse.")
            if not reasons:
                reasons.append("Detected suspicious patterns matching known phishing sites.")
        else:
            reasons.append("URL structure appears legitimate.")
            
        return reasons

    def train(self):
        loader = DataLoader()
        df = loader.get_data()

        if df.empty:
            raise ValueError("Training dataset is empty. Could not train model.")

        # Basic cleanup and canonicalization before feature extraction.
        df = df[['url', 'label']].dropna()
        df['url'] = df['url'].astype(str).str.strip()
        df = df[df['url'] != '']
        df['normalized_url'] = df['url'].apply(self.normalize_url)
        df = df[df['normalized_url'] != '']

        # If duplicate URLs have conflicting labels, keep malicious label as safer default.
        df = df.groupby('normalized_url', as_index=False)['label'].max()
        df = df.rename(columns={'normalized_url': 'url'})

        if df['label'].nunique() < 2:
            raise ValueError("Training requires both benign and malicious samples.")
        
        print("Extracting features...")
        X = np.array([self.extract_features(url) for url in df['url']])
        y = df['label'].values

        # Group by registered-like domain to reduce optimistic leakage in evaluation.
        groups = [self._domain_group(urlparse(u).netloc) for u in df['url']]
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, test_idx = next(splitter.split(X, y, groups=groups))
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        print("Training Random Forest...")
        self.model.fit(X_train, y_train)
        
        preds = self.model.predict(X_test)
        probs = self.model.predict_proba(X_test)[:, 1]
        accuracy = accuracy_score(y_test, preds)
        precision = precision_score(y_test, preds, zero_division=0)
        recall = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)
        auc = roc_auc_score(y_test, probs)

        print(f"Model Accuracy: {accuracy}")
        print(f"Precision: {precision}")
        print(f"Recall: {recall}")
        print(f"F1 Score: {f1}")
        print(f"ROC-AUC: {auc}")
        print(classification_report(y_test, preds))
        
        # Save model
        joblib.dump(self.model, 'phishing_model.pkl')
        print("Model saved to phishing_model.pkl")
        return accuracy

if __name__ == "__main__":
    detector = PhishingDetector()
    detector.train()
