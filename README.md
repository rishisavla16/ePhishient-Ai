ePhishient AI – Phishing URL Detection System

ePhishient AI is a machine learning–based web application that detects phishing URLs in real time.
The system evaluates the lexical structure of a URL to estimate whether it is malicious, returning a confidence score along with a transparent breakdown of contributing risk factors.



Features

* Real-Time URL Analysis
  Classifies URLs instantly using a trained Random Forest model.

* Lexical Feature-Based Detection
  Extracts over 20 structural and statistical features without visiting or executing content from the target URL.

* On-Demand Model Retraining
  Administrators can retrain the model directly from the web interface using updated threat intelligence feeds.

* Responsive User Interface
  Fully responsive frontend with optional dark mode support.

* Result Exporting
  Analysis results can be copied to the clipboard or exported as a PDF.

* Live Threat Intelligence Integration
  Training data is fetched dynamically from reputable phishing and benign URL sources.



Technical Architecture

The application uses Python (Flask) for the backend and HTML, CSS, and JavaScript for the frontend.



Data Collection (data_loader.py)

The system aggregates URLs from multiple sources to build a balanced dataset.

Malicious URL Sources

* PhishTank – Verified phishing URLs
* OpenPhish – Active phishing feed
* URLhaus – Malware distribution URLs

Benign URL Source

* Tranco Top Sites List (top 3,000 domains used)

Dataset Balancing

* Ensures equal representation of benign and malicious samples to reduce model bias.



Feature Engineering (train_model.py)

Instead of relying on static blacklists, the model evaluates the structural properties of URLs.
The PhishingDetector class extracts 20 lexical features, including:

Structural Features

* Total URL length
* Hostname length
* Path length
* Top-level domain (TLD) length

Statistical Features

* Frequency of special characters such as -, @, ?, %, ., =, &, and _

Entropy Analysis

* Measures randomness within the URL string, often associated with algorithmically generated phishing links.

Heuristic Indicators

* Presence of IP addresses in hostnames
* Use of URL shorteners
* Sensitive keywords such as login, secure, or account



Machine Learning Model

* Algorithm: Random Forest Classifier
* Library: sklearn.ensemble.RandomForestClassifier
* Training: Performed on the extracted lexical feature set
* Evaluation: Domain-grouped holdout split to reduce train/test leakage
* Metrics: Accuracy, Precision, Recall, F1, ROC-AUC printed at training time
* Persistence: The trained model is serialized as phishing_model.pkl for fast inference



Web Application (app.py)

Framework

* Flask

Endpoints

* / : Renders the main user interface
* /predict : Accepts a URL, extracts features, and returns classification, risk score, and confidence
* /retrain : Executes the data collection and training pipeline in the background



Frontend (templates and static)

User Interaction

* URLs are submitted via AJAX fetch requests.

Visualization

* Displays risk level, confidence percentage, and individual risk indicators.

Utilities

* Dark mode toggle
* Clipboard copying
* PDF report generation using jsPDF



Usage Guide

1. Enter a URL into the input field.
2. Submit the URL for analysis.
3. Review the classification result, confidence score, and detected risk factors.
4. Export or share the results if needed.
5. Retrain the model when updated threat data is required.



Security Considerations

This application analyzes only the textual structure of URLs.
It does not fetch page content, execute scripts, or render external resources, making it safe for evaluating potentially malicious links.
