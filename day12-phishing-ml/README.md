# Day 12 — Phishing Email Detection with Machine Learning

**Sqrock Cybersecurity Internship — Phase 1**

## Overview

Day 12 implements a machine-learning-based phishing email classifier using Python and scikit-learn.

The project demonstrates a complete basic NLP/ML workflow:

1. Load a labeled email dataset.
2. Validate the dataset.
3. Split the data into training and testing sets.
4. Convert email text into numerical TF-IDF features.
5. Train a Multinomial Naive Bayes classifier.
6. Evaluate the model on a held-out test set.
7. Perform stratified cross-validation.
8. Generate predictions with probability/confidence scores.
9. Export machine-readable JSON results and a human-readable classification report.

The dataset used in this project is **synthetic and intended for cybersecurity training only**.

---

## Learning Objectives

- Understand basic text classification for phishing detection.
- Learn how TF-IDF converts text into numerical features.
- Understand the Multinomial Naive Bayes algorithm for text classification.
- Separate training and testing data.
- Evaluate a classifier using accuracy, precision, recall, and F1-score.
- Use stratified cross-validation.
- Interpret phishing probability/confidence.
- Understand the limitations of small synthetic datasets.

---

## Project Structure

```text
day12-phishing-ml/
├── input/
│   └── emails.csv
├── output/
│   ├── classification_report.txt
│   ├── model_results.json
│   └── predictions.json
├── phishing_email_classifier.py
├── README.md
├── report/
│   └── day12-report.md
├── requirements.txt
└── screenshots/
Requirements
Python 3.10+
scikit-learn
pandas

Install dependencies:

python3 -m pip install -r requirements.txt

A Python virtual environment is recommended:

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
Dataset

The project uses:

input/emails.csv

The dataset contains:

160 synthetic emails
80 legitimate emails
80 phishing emails

Each record contains an email text and its corresponding classification label.

Labels:

0 = Legitimate
1 = Phishing

The dataset is intentionally synthetic and relatively small.

Machine Learning Pipeline

The classifier uses the following pipeline:

Email Text
    │
    ▼
TF-IDF Vectorization
    │
    ▼
Multinomial Naive Bayes
    │
    ▼
Phishing / Legitimate Prediction
    │
    ▼
Probability + Evaluation Metrics
TF-IDF

TF-IDF represents text numerically based on how important words are within the dataset.

It gives greater importance to terms that are useful for distinguishing documents while reducing the influence of extremely common terms.

Multinomial Naive Bayes

Multinomial Naive Bayes is a lightweight probabilistic classifier commonly used for text classification.

It is suitable for this training exercise because it is:

Fast
Simple
Interpretable
Effective for many basic text-classification tasks
Running the Classifier

Run the standard analysis:

python3 phishing_email_classifier.py

Run with verbose logging:

python3 phishing_email_classifier.py --verbose

The program produces:

output/model_results.json
output/predictions.json
output/classification_report.txt
Results

The current synthetic dataset produced:

Dataset       : 160 synthetic emails
Test accuracy : 100.00%
Phishing F1   : 100.00%
CV mean F1    : 100.00%

Held-out test set:

Training samples: 120
Testing samples : 40

Confusion matrix:

              Predicted
              LEGIT  PHISHING

Actual LEGIT    20       0
Actual PHISHING  0      20

The classifier therefore correctly classified all 40 samples in the held-out test set.

Five-fold stratified cross-validation also produced:

F1 scores: [1.0, 1.0, 1.0, 1.0, 1.0]
Mean F1  : 100.00%
Std F1   : 0.00%
Example Predictions

Example phishing email:

Urgent security alert: verify your PayPal password immediately using the secure link.

Prediction:

PHISHING
Confidence: 98.08%

Example legitimate email:

Hi team, the project meeting is confirmed for Tuesday at 3 PM. The agenda is attached.

Prediction:

LEGIT
Confidence: 97.10%

Another phishing example:

Your bank account will be suspended today unless you confirm your payment details.

Prediction:

PHISHING
Confidence: 99.47%
Output Files
model_results.json

Contains:

Dataset metadata
Dataset size
Class distribution
Test-set metrics
Confusion matrix
Classification report
Cross-validation results
predictions.json

Contains:

Test/sample email text
Predicted class
Class label
Model confidence
Phishing probability
Legitimate probability
classification_report.txt

Contains a human-readable summary of the model evaluation.

Security Interpretation

The project demonstrates how machine learning can assist with phishing detection.

Potential phishing indicators include:

Urgency
Account verification requests
Password requests
Financial threats
Suspicious calls to action
Requests to click links
Requests for sensitive information

However, text classification alone is not sufficient for production-grade phishing detection.

A real detection system should consider additional signals such as:

Sender authentication
Domain reputation
URL analysis
Attachment analysis
Email headers
SPF/DKIM/DMARC results
Known malicious infrastructure
Historical sender behavior
User reports
Human review
Important Limitation

The dataset used by this project is:

Synthetic
Relatively small
Artificially balanced
Designed for educational purposes

The observed 100% accuracy and F1-score demonstrate that the ML workflow is functioning correctly on this dataset.

They must not be interpreted as 100% real-world phishing detection performance.

A production-quality model would require a much larger and more diverse dataset containing real-world examples, temporal validation, continuous retraining, and additional email/security signals.

Ethical and Safety Considerations

This project is an educational cybersecurity exercise.

The classifier does not send emails, interact with real accounts, collect credentials, or perform attacks against external systems.

Synthetic data is used to demonstrate phishing detection concepts safely.

Skills Demonstrated
Python
pandas
scikit-learn
NLP preprocessing
TF-IDF
Multinomial Naive Bayes
Supervised machine learning
Train/test splitting
Stratified cross-validation
Classification metrics
Confusion matrices
Probability-based predictions
JSON reporting
Cybersecurity awareness
Conclusion

Day 12 demonstrates a complete introductory ML workflow for phishing email classification.

The project successfully loads labeled email data, trains a TF-IDF + Multinomial Naive Bayes model, evaluates it using held-out testing and cross-validation, and exports structured results.

The most important takeaway is that model evaluation results are only meaningful within the context of the dataset and validation methodology used.
