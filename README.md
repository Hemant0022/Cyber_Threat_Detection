For Model_Train.py file:
LSTM-based Intrusion Detection System using NSL-KDD Dataset
===========================================================

This project implements a deep learning-based Intrusion Detection System (IDS) using an LSTM Autoencoder for anomaly detection and a supervised LSTM model for multi-class classification. It is trained and evaluated using the NSL-KDD dataset.

Project Structure
-----------------
.
├── models/                         # Stores trained models and scaler
│   ├── lstm_autoencoder.h5        # Saved LSTM autoencoder model
│   ├── scaler.pkl                 # Saved scaler object for preprocessing
│   ├── NSL_KDD_Train.csv          # NSL-KDD training data
│   └── NSL_KDD_Test.csv           # NSL-KDD testing data
├── nsl_kdd_processor.py           # Main file for data processing and model training
├── README.txt                     # Project documentation (you are here)

Features
--------
- Preprocessing: Scales numerical data and encodes categorical features.
- Binary Classification: Uses LSTM Autoencoder to detect anomalies (attacks vs benign).
- Multi-Class Classification: Detects specific attack types like DDoS, Malware, PortScan, etc.
- Model Saving: Stores trained models and scalers for reuse.
- Visualization: Generates a reconstruction error histogram to visualize detection capability.

Requirements
------------
Install the dependencies using:

    pip install -r requirements.txt

Required Libraries:
- numpy
- pandas
- tensorflow
- scikit-learn
- matplotlib
- seaborn

Training the Models
-------------------

Binary Classification (Autoencoder):

    from nsl_kdd_processor import NSLKDDProcessor

    processor = NSLKDDProcessor()
    train_df, test_df = processor.load_data()
    X_train, X_test, y_test, feature_cols = processor.preprocess_data(train_df, test_df, for_autoencoder=True)
    processor.train_autoencoder(X_train, X_test, y_test)

Multi-Class Classification:

    X_train, y_train, X_test, y_test, feature_cols = processor.preprocess_data(train_df, test_df, for_autoencoder=False)
    X_train_reshaped, X_test_reshaped = processor.reshape_for_lstm(X_train, X_test)
    model = processor.build_multiclass_model(input_shape=X_train_reshaped.shape[1:], num_classes=5)
    model.fit(X_train_reshaped, y_train, epochs=50, batch_size=32, validation_split=0.2)

Output
------
- reconstruction_error_dist.png: Visualization of reconstruction errors for benign and attack data.
- lstm_autoencoder.h5: Trained autoencoder model saved in the `models/` directory.
- scaler.pkl: Scaler object used for preprocessing.

Dataset Source
--------------
The NSL-KDD dataset used in this project can be downloaded from:
https://www.unb.ca/cic/datasets/nsl.html

Make sure to place NSL_KDD_Train.csv and NSL_KDD_Test.csv in the models/ directory.

Attack Categories
-----------------
| Attack Type      | Category   |
|------------------|------------|
| normal           | Benign     |
| neptune          | DDoS       |
| smurf            | DDoS       |
| buffer_overflow  | Malware    |
| portsweep        | PortScan   |
| guess_passwd     | Phishing   |
| ...              | ...        |

(Full mappings can be found inside the script.)


For Detection file:

🛡️Cyber Threat Detection System
====================================================

This project is a real-time cyber threat detection system built using Streamlit, LSTM models, and multithreading.
It simulates network traffic, classifies it as benign or malicious using machine learning models, and displays live 
visualizations and alerts in an interactive dashboard.

----------------------------------------------------
🚀 Features
----------------------------------------------------
- Real-time monitoring of network packet data
- LSTM-based threat classification
- Synthetic traffic simulation with adjustable attack rate
- Live scatter and pie charts for packet and threat visualization
- Modular model loading (supports both LSTM and Scikit-learn models)
- Threat logs and alerts with timestamps
- Email notifications for critical threats (optional)
- Multithreading for smooth UI updates and data simulation

----------------------------------------------------
🧩 Project Structure
----------------------------------------------------
.
├── Threat_detect.py                 # Main Streamlit dashboard app
├── models/
│   ├── lstm_model.pt       # Pretrained LSTM model (PyTorch)
│   └── ...                 # Other models (e.g., sklearn .pkl)
├── utils/
│   ├── packet_generator.py # Simulates network traffic
│   ├── threat_classifier.py# Handles classification logic
│   ├── logger.py           # Logging and alert system
│   └── model_loader.py     # Loads LSTM / sklearn models
└── requirements.txt        # Python dependencies

----------------------------------------------------
🛠️ Setup Instructions
----------------------------------------------------
1. Clone the repository
   git clone https://github.com/your-username/cyber-threat-detection.git
   cd cyber-threat-detection

2. Install dependencies
   pip install -r requirements.txt

3. Add your models
   - Put your trained LSTM model (.pt) and/or Scikit-learn model (.pkl) inside the models/ folder.

4. Run the app
   streamlit run Threat_detect.py

----------------------------------------------------
⚙️ Controls
----------------------------------------------------
- Active Monitoring: Toggle live packet simulation.
- Attack Simulation Rate: Adjust probability of simulated attacks (0 to 1).
- Refresh Interval: Control how often the dashboard updates.
----------------------------------------------------
📌 Future Enhancements
----------------------------------------------------
- Real packet sniffing with tools like scapy
- Threat severity scoring
- Role-based access and authentication
- Historical data export (CSV/JSON)

----------------------------------------------------
📚 Tech Stack(Libraries)
----------------------------------------------------
- Python
- Streamlit
- PyTorch (for LSTM)
- Scikit-learn
- Multithreading
- Matplotlib / Plotly

