# Day 12 — Phishing Email Detection with Machine Learning

**Sqrock Cybersecurity Internship — Phase 1**

---

## 1. Objective

The objective of Day 12 was to build a basic machine-learning classifier capable of distinguishing phishing emails from legitimate emails.

The project uses natural-language processing techniques to transform email text into numerical features and a Multinomial Naive Bayes classifier to perform the classification.

The implementation also evaluates the model using:

- Held-out test data
- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- Five-fold stratified cross-validation
- Prediction probabilities

---

## 2. Environment

Operating system:

```text
Parrot OS
Python environment:

Python 3

Machine-learning framework:

scikit-learn

Data processing:

pandas
3. Dataset

The project uses a synthetic dataset stored at:

input/emails.csv

Dataset size:

160 emails

Class distribution:

Legitimate : 80
Phishing   : 80

Labels:

0 = Legitimate
1 = Phishing

The dataset was created specifically for cybersecurity training and demonstration purposes.

4. Methodology

The classifier follows this workflow:

Synthetic Email Dataset
        │
        ▼
Dataset Validation
        │
        ▼
Stratified Train/Test Split
        │
        ├── Training Set
        │
        └── Testing Set
                │
                ▼
        TF-IDF Vectorization
                │
                ▼
      Multinomial Naive Bayes
                │
                ▼
          Classification
                │
                ▼
        Model Evaluation
5. Feature Extraction

The model uses TF-IDF vectorization to convert email text into numerical features.

TF-IDF stands for:

Term Frequency — Inverse Document Frequency

The technique provides a numerical representation of text that can be processed by a machine-learning algorithm.

This allows the classifier to learn associations between textual patterns and the two target classes:

LEGIT
PHISHING
6. Classification Algorithm

The project uses:

Multinomial Naive Bayes

Multinomial Naive Bayes is a probabilistic classification algorithm that works particularly well with discrete text features.

It was selected because it is:

Fast
Lightweight
Easy to implement
Appropriate for introductory text classification
Suitable for demonstrating probabilistic classification
7. Train/Test Split

The dataset contains:

160 total samples

The implementation uses a 75/25 split.

Therefore:

Training samples: 120
Testing samples : 40

The test set contains:

20 legitimate emails
20 phishing emails

The test data is kept separate from the training process so that the model can be evaluated on previously unseen samples.

8. Held-Out Test Results

The classifier achieved the following results on the held-out test set:

Accuracy:             100.00%
Precision (Phishing): 100.00%
Recall (Phishing):    100.00%
F1 (Phishing):        100.00%

These results indicate that all 40 test samples were classified correctly.

9. Confusion Matrix

The resulting confusion matrix was:

Rows    = Actual
Columns = Predicted

              LEGIT  PHISHING

LEGIT           20       0

PHISHING         0      20

Interpretation:

20 legitimate messages were correctly classified as legitimate.
20 phishing messages were correctly classified as phishing.
No false positives occurred in this test set.
No false negatives occurred in this test set.
10. Classification Report

The classification report produced:

              precision    recall  f1-score   support

LEGIT            1.00      1.00      1.00        20
PHISHING         1.00      1.00      1.00        20

accuracy                              1.00        40
macro avg        1.00      1.00      1.00        40
weighted avg     1.00      1.00      1.00        40
11. Cross-Validation

To provide an additional evaluation of the model, five-fold stratified cross-validation was performed.

Results:

Folds:     5

F1 scores:
[1.0, 1.0, 1.0, 1.0, 1.0]

Mean F1:
100.00%

Standard deviation:
0.00%

Stratification maintains the class distribution across the folds.

The identical scores demonstrate consistent performance across the five folds of this particular synthetic dataset.

12. Sample Predictions
Sample 1

Input:

Urgent security alert: verify your PayPal password immediately using the secure link.

Prediction:

PHISHING

Confidence:

98.08%
Sample 2

Input:

Hi team, the project meeting is confirmed for Tuesday at 3 PM. The agenda is attached.

Prediction:

LEGIT

Confidence:

97.10%
Sample 3

Input:

Your bank account will be suspended today unless you confirm your payment details.

Prediction:

PHISHING

Confidence:

99.47%
Sample 4

Input:

Please review the quarterly budget document before tomorrow's planning meeting.

Prediction:

LEGIT

Confidence:

96.42%
13. Output Artifacts

The implementation generated three primary output files.

Model Metrics
output/model_results.json

Contains:

Dataset metadata
Class distribution
Test metrics
Confusion matrix
Classification report
Cross-validation results
Predictions
output/predictions.json

Contains:

Email text
Predicted class
Label
Confidence
Phishing probability
Legitimate probability
Human-Readable Report
output/classification_report.txt

Contains the evaluation results in a readable text format.

14. Security Relevance

Phishing attacks commonly attempt to manipulate users through social engineering techniques such as:

Urgency
Fear of account closure
Requests for password verification
Requests for financial information
Suspicious links
Requests to perform immediate actions

A machine-learning classifier can potentially assist security systems by identifying patterns associated with suspicious messages.

However, classification based only on email text has significant limitations.

A stronger production system would combine text analysis with other security signals.

15. Production Considerations

A production phishing detection system would require additional data and analysis.

Potential improvements include:

Larger training datasets
More diverse phishing campaigns
Realistic legitimate business communications
Temporal validation
Continuous model retraining
Sender reputation
SPF/DKIM/DMARC analysis
URL reputation
Domain age and reputation
Attachment analysis
Email-header analysis
Malware scanning
User-report feedback
Human review for uncertain cases
16. Important Limitation

The most important limitation of this project is the dataset.

The dataset contains only:

160 synthetic emails

and is evenly divided between phishing and legitimate examples.

The model achieved:

100% test accuracy
100% phishing precision
100% phishing recall
100% phishing F1
100% mean cross-validation F1

These results demonstrate that the implementation successfully learned the patterns represented in this synthetic dataset.

They do not demonstrate 100% real-world phishing detection capability.

A small, synthetic, balanced dataset can be substantially easier to classify than real-world email traffic.

Therefore, the results should be interpreted as a demonstration of the machine-learning workflow rather than a production benchmark.

17. Ethical Considerations

The project uses synthetic email data and does not interact with real email accounts or users.

No credentials are collected.

No real phishing campaign is conducted.

The purpose of the project is defensive cybersecurity education and awareness.

18. Skills Demonstrated

During this task, the following concepts were implemented:

Python machine learning
pandas dataset processing
scikit-learn
Natural Language Processing
TF-IDF
Multinomial Naive Bayes
Supervised classification
Train/test splitting
Stratified cross-validation
Accuracy
Precision
Recall
F1-score
Confusion matrices
Probability estimation
JSON reporting
Cybersecurity analysis
19. Conclusion

Day 12 successfully demonstrates an end-to-end machine-learning workflow for phishing email classification.

The system loads a labeled synthetic dataset, transforms email text into TF-IDF features, trains a Multinomial Naive Bayes classifier, evaluates the model using a held-out test set and five-fold stratified cross-validation, and exports structured results.

The model achieved perfect metrics on the supplied synthetic dataset.

The key cybersecurity lesson is that high evaluation scores must always be interpreted in the context of dataset size, diversity, quality, and validation methodology.

The next step toward a production-quality detector would be evaluation against a substantially larger and more diverse dataset containing realistic phishing and legitimate email samples.
