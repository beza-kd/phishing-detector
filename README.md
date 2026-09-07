# 🛡️ Phishing Detector

**A machine learning-based system for detecting potentially phishing URLs.**

Phishing Detector uses a **Random Forest machine learning model** to analyze URL characteristics and predict whether a URL is **phishing or legitimate**.

The project combines machine learning, cybersecurity, and web development into a simple application that allows users to check URLs in real time.

---

## 🚀 Features

* 🔍 **Phishing URL Detection** — Classifies URLs as phishing or legitimate
* 🤖 **Machine Learning** — Uses a trained Random Forest classifier
* ⚡ **Real-Time Prediction** — Analyze URLs instantly
* 🌐 **Web Interface** — Simple interface for entering and checking URLs
* 📊 **URL Feature Analysis** — Uses characteristics of URLs to make predictions

---

## 🧠 How It Works

The system follows a simple machine learning pipeline:

```text
             User enters a URL
                    │
                    ▼
            Feature Extraction
                    │
                    ▼
          Random Forest Classifier
                    │
                    ▼
               Prediction
              /          \
             ▼            ▼
        Phishing       Legitimate
```

The model is trained using a dataset containing examples of phishing and legitimate URLs. During prediction, URL features are extracted and passed to the trained Random Forest model.

---

## 🛠️ Technologies

| Technology      | Purpose                     |
| --------------- | --------------------------- |
| 🐍 Python       | Core programming language   |
| 🌲 Scikit-learn | Machine learning model      |
| 🐼 Pandas       | Data processing             |
| 🔢 NumPy        | Numerical operations        |
| 🌐 HTML/CSS     | User interface              |
| ⚡ Flask         | Web application *(if used)* |

---

## 📁 Project Structure

```text
phishing-detector/
│
├── app.py
├── final.py
│
├── model/
│   └── detection_rf_model.pkl
│
├── templates/
│   └── phishing.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── data/
│   └── README.md
│
├── screenshots/
│   └── prediction.png
│
├── requirements.txt
├── .gitignore
├── README.md
└── LICENSE
```

### Key Files

* **`app.py`** — Runs the web application
* **`final.py`** — Contains the core URL detection logic
* **`detection_rf_model.pkl`** — Trained Random Forest model
* **`phishing.html`** — Main web interface
* **`requirements.txt`** — Python dependencies
* **`.gitignore`** — Files excluded from version control

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/phishing-detector.git
cd phishing-detector
```

### 2. Install the required packages

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python app.py
```

Open the local URL provided by the application in your browser.

---

## 📊 Machine Learning Model

The project uses a **Random Forest Classifier** for phishing URL classification.

Random Forest was selected because it can handle multiple URL-related features and is well suited for classification tasks.

The model was trained using phishing URL data and learns patterns that can help distinguish suspicious URLs from legitimate ones.

### Model Performance

> **Accuracy:** Add your actual test-set accuracy here.

For example:

```text
Accuracy: XX.XX%
Precision: XX.XX%
Recall: XX.XX%
F1 Score: XX.XX%
```

**Important:** Only add these numbers after calculating them from your actual test results.

---

## 🖥️ Application Preview

Add screenshots of your application here:

```markdown
![Phishing Detector](screenshots/prediction.png)
```

A screenshot or short demo GIF is recommended because it lets visitors immediately see what you built.

---

## 🔮 Future Improvements

Some improvements I plan to explore:

* Improve URL feature extraction
* Experiment with additional machine learning algorithms
* Improve model evaluation and testing
* Add more training data
* Improve the web interface
* Add model performance visualizations
* Deploy the application online
* Explore additional URL reputation checks

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes**.

Machine learning-based phishing detection is not perfect. The system may produce false positives or false negatives, so predictions should not be treated as definitive proof that a website is safe or malicious.

---

## 👩‍💻 Author

### Bezawit

Student developer interested in:

**Machine Learning • Cybersecurity • Web Development • Software Engineering**

---

## 📄 License

This project is licensed under the **MIT License**.
