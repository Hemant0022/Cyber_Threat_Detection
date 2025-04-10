import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import Input, LSTM, Dense, RepeatVector, TimeDistributed, Dropout
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, TensorBoard
from sklearn.preprocessing import StandardScaler, MinMaxScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_curve, roc_curve, \
    auc
import matplotlib.pyplot as plt
import seaborn as sns
import os
import pickle
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NSLKDDProcessor:
    def __init__(self, data_path='./models/'):
        self.data_path = data_path
        self.train_path = os.path.join(data_path, 'NSL_KDD_Train.csv')
        self.test_path = os.path.join(data_path, 'NSL_KDD_Test.csv')
        self.model_path = './models/'
        self.scaler_path = './models/scaler.pkl'

        # Create model directory if it doesn't exist
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)

        # These column names match the NSL-KDD dataset format
        self.column_names = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
            "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
            "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
            "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
            "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
        ]

        # For LSTM, we need to determine which columns are categorical vs numerical
        self.categorical_cols = ['protocol_type', 'service', 'flag']
        self.numerical_cols = [col for col in self.column_names if col not in self.categorical_cols + ['label']]

        # Attack type grouping for multi-class classification
        self.attack_dict = {
            'normal': 'Benign',
            'neptune': 'DDoS',
            'back': 'DDoS',
            'land': 'DDoS',
            'pod': 'DDoS',
            'smurf': 'DDoS',
            'teardrop': 'DDoS',
            'mailbomb': 'DDoS',
            'apache2': 'DDoS',
            'processtable': 'DDoS',
            'udpstorm': 'DDoS',
            'worm': 'Malware',
            'buffer_overflow': 'Malware',
            'loadmodule': 'Malware',
            'perl': 'Malware',
            'rootkit': 'Malware',
            'xterm': 'Malware',
            'ps': 'Malware',
            'httptunnel': 'Malware',
            'sqlattack': 'Malware',
            'ipsweep': 'PortScan',
            'nmap': 'PortScan',
            'portsweep': 'PortScan',
            'satan': 'PortScan',
            'mscan': 'PortScan',
            'saint': 'PortScan',
            'ftp_write': 'Phishing',
            'guess_passwd': 'Phishing',
            'imap': 'Phishing',
            'multihop': 'Phishing',
            'phf': 'Phishing',
            'spy': 'Phishing',
            'warezclient': 'Phishing',
            'warezmaster': 'Phishing',
            'snmpgetattack': 'Phishing',
            'named': 'Phishing',
            'xlock': 'Phishing',
            'xsnoop': 'Phishing',
            'sendmail': 'Phishing',
            'snmpguess': 'Phishing'
        }

        self.attack_mapping = {
            'Benign': 0,
            'DDoS': 1,
            'Malware': 2,
            'PortScan': 3,
            'Phishing': 4
        }

        # Tracking the data preparation steps
        self.scaler = None
        self.categorical_encoders = {}

    def load_data(self):
        """Load NSL-KDD dataset from files"""
        logger.info("Loading NSL-KDD dataset...")

        try:
            # Load training data
            train_df = pd.read_csv(self.train_path, header=None, names=self.column_names)

            # Load testing data
            test_df = pd.read_csv(self.test_path, header=None, names=self.column_names)

            logger.info(f"Training data shape: {train_df.shape}")
            logger.info(f"Testing data shape: {test_df.shape}")

            return train_df, test_df

        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise

    def preprocess_data(self, train_df, test_df, for_autoencoder=True):
        """Preprocess the data for LSTM training with autoencoder"""
        logger.info("Preprocessing data...")

        # Make a copy to avoid modifying original dataframes
        train = train_df.copy()
        test = test_df.copy()

        # Normalize attack labels to the 5 categories used in the dashboard
        train['attack_cat'] = train['label'].str.split('.').str[0].map(self.attack_dict)
        test['attack_cat'] = test['label'].str.split('.').str[0].map(self.attack_dict)

        # For binary classification (anomaly detection with autoencoder)
        train['binary_label'] = train['attack_cat'].apply(lambda x: 0 if x == 'Benign' else 1)
        test['binary_label'] = test['attack_cat'].apply(lambda x: 0 if x == 'Benign' else 1)

        # Convert attack categories to numeric for multi-class classification
        train['attack_cat_code'] = train['attack_cat'].map(self.attack_mapping)
        test['attack_cat_code'] = test['attack_cat'].map(self.attack_mapping)

        # Handle categorical features
        for cat_col in self.categorical_cols:
            # Create one-hot encoding for each categorical column
            encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
            train_encoded = encoder.fit_transform(train[[cat_col]])
            test_encoded = encoder.transform(test[[cat_col]])

            # Create column names for one-hot encoded features
            enc_cols = [f"{cat_col}_{category}" for category in encoder.categories_[0]]

            # Create dataframes with encoded columns
            train_encoded_df = pd.DataFrame(train_encoded, columns=enc_cols, index=train.index)
            test_encoded_df = pd.DataFrame(test_encoded, columns=enc_cols, index=test.index)

            # Add the encoded columns to original dataframes
            train = pd.concat([train, train_encoded_df], axis=1)
            test = pd.concat([test, test_encoded_df], axis=1)

            # Store encoder for future use
            self.categorical_encoders[cat_col] = encoder

        # Scale numerical features
        self.scaler = MinMaxScaler()
        train[self.numerical_cols] = self.scaler.fit_transform(train[self.numerical_cols])
        test[self.numerical_cols] = self.scaler.transform(test[self.numerical_cols])

        # Save the scaler for future use in the dashboard
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

        # Prepare feature sets (excluding original categorical cols and target columns)
        exclude_cols = self.categorical_cols + ['label', 'attack_cat', 'binary_label', 'attack_cat_code']
        feature_cols = [col for col in train.columns if col not in exclude_cols]

        # For autoencoder training, we only use benign data
        if for_autoencoder:
            # Use only benign data for training the autoencoder
            X_train_benign = train[train['binary_label'] == 0][feature_cols].values

            # We'll use a mix of benign and malicious data for validation
            X_test = test[feature_cols].values
            y_test = test['binary_label'].values

            # X_train will be used for unsupervised learning
            # X_test and y_test will be used to set a threshold and evaluate
            return X_train_benign, X_test, y_test, feature_cols
        else:
            # For supervised model, we use all data
            X_train = train[feature_cols].values
            y_train = train['attack_cat_code'].values
            X_test = test[feature_cols].values
            y_test = test['attack_cat_code'].values

            return X_train, y_train, X_test, y_test, feature_cols

    def reshape_for_lstm(self, X_train, X_test):
        """Reshape data for LSTM input - converts 2D to 3D by adding a time dimension"""
        # LSTM expects input in the form [samples, timesteps, features]
        # We'll use a single timestep since we're not actually working with time-series
        X_train_reshaped = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
        X_test_reshaped = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])

        return X_train_reshaped, X_test_reshaped

    def build_autoencoder(self, input_shape, encoding_dim=32):
        """Build LSTM Autoencoder model for anomaly detection"""
        # Input layer
        inputs = Input(shape=input_shape)

        # Encoder layers
        encoded = LSTM(64, activation='relu', return_sequences=True)(inputs)
        encoded = Dropout(0.2)(encoded)
        encoded = LSTM(32, activation='relu', return_sequences=False)(encoded)

        # Bottleneck layer (the encoded representation)
        encoded = Dense(encoding_dim, activation='relu')(encoded)

        # Decoder layers
        decoded = RepeatVector(input_shape[0])(encoded)
        decoded = LSTM(32, activation='relu', return_sequences=True)(decoded)
        decoded = Dropout(0.2)(decoded)
        decoded = LSTM(64, activation='relu', return_sequences=True)(decoded)

        # Output layer (reconstructing the input)
        outputs = TimeDistributed(Dense(input_shape[1]))(decoded)

        # Create the autoencoder model
        autoencoder = Model(inputs, outputs)

        # Use the full loss function object instead of the string
        autoencoder.compile(optimizer='adam', loss=tf.keras.losses.MeanSquaredError())

        return autoencoder

    def build_multiclass_model(self, input_shape, num_classes=5):
        """Build LSTM model for multiclass classification"""
        model = Sequential([
            LSTM(128, input_shape=input_shape, return_sequences=True, activation='relu'),
            Dropout(0.2),
            LSTM(64, return_sequences=False, activation='relu'),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dense(num_classes, activation='softmax')
        ])

        model.compile(
            loss='sparse_categorical_crossentropy',
            optimizer='adam',
            metrics=['accuracy']
        )

        return model

    def train_autoencoder(self, X_train, X_test, y_test, epochs=50, batch_size=32):
        """Train the LSTM Autoencoder model and determine threshold for anomaly detection"""
        # Reshape data for LSTM
        X_train_reshaped, X_test_reshaped = self.reshape_for_lstm(X_train, X_test)

        logger.info(f"Training data shape after reshaping: {X_train_reshaped.shape}")

        # Get the input shape from reshaped data
        input_shape = X_train_reshaped.shape[1:]

        # Build the autoencoder model
        autoencoder = self.build_autoencoder(input_shape)

        # Print model summary
        autoencoder.summary()

        # Set up model checkpoints
        model_checkpoint = ModelCheckpoint(
            filepath=os.path.join(self.model_path, 'lstm_autoencoder.h5'),
            monitor='val_loss',
            save_best_only=True,
            verbose=1
        )

        # Early stopping to prevent overfitting
        early_stopping = EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True,
            verbose=1
        )

        # Start training
        logger.info("Training LSTM Autoencoder...")
        start_time = time.time()

        history = autoencoder.fit(
            X_train_reshaped, X_train_reshaped,  # Autoencoder tries to reconstruct its input
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,  # Use 20% of training data for validation
            callbacks=[model_checkpoint, early_stopping],
            verbose=1
        )

        training_time = time.time() - start_time
        logger.info(f"Training completed in {training_time:.2f} seconds")

        # Load the best model
        # Use the autoencoder that was already trained - no need to reload
        logger.info("Using the best model from training")

        # Calculate reconstruction error on the test set
        # For LSTM autoencoder, we need the reshaped test data
        reconstructions = autoencoder.predict(X_test_reshaped)

        # Convert back to 2D for calculating MSE
        # We take the first (and only) timestep
        reconstructions_2d = reconstructions.reshape(reconstructions.shape[0], reconstructions.shape[2])

        # Calculate reconstruction error
        mse = np.mean(np.power(X_test - reconstructions_2d, 2), axis=1)

        # Plot reconstruction error distribution
        plt.figure(figsize=(12, 6))
        plt.hist(mse[y_test == 0], bins=50, alpha=0.5, label='Benign (0)')
        plt.hist(mse[y_test == 1], bins=50, alpha=0.5, label='Attack (1)')
        plt.xlabel('Reconstruction Error (MSE)')
        plt.ylabel('Count')
        plt.legend()
        plt.title('Reconstruction Error Distribution')
        plt.savefig(os.path.join(self.model_path, 'reconstruction_error_dist.png'))

        # Find the optimal threshold using precision-recall curve
        precision, recall, thresholds = precision_recall_curve(y_test, mse)

        # Find threshold that maximizes F1 score
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_threshold_idx = np.argmax(f1_scores)
        optimal_threshold = thresholds[optimal_threshold_idx]

        logger.info(f"Optimal threshold: {optimal_threshold:.6f}")

        # Save the threshold
        np.save(os.path.join(self.model_path, 'anomaly_threshold.npy'), optimal_threshold)

        # Evaluate the model using the threshold
        predictions = (mse > optimal_threshold).astype(int)

        # Print classification report
        logger.info("Classification Report:")
        logger.info(classification_report(y_test, predictions))

        # Print confusion matrix
        conf_matrix = confusion_matrix(y_test, predictions)
        logger.info("Confusion Matrix:")
        logger.info(conf_matrix)

        # Plot the training history
        plt.figure(figsize=(12, 4))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['loss'])
        plt.plot(history.history['val_loss'])
        plt.title('Model Loss During Training')
        plt.ylabel('Loss')
        plt.xlabel('Epoch')
        plt.legend(['Train', 'Validation'], loc='upper right')

        # Plot ROC curve
        plt.subplot(1, 2, 2)
        fpr, tpr, _ = roc_curve(y_test, mse)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f'AUC = {roc_auc:.3f}')
        plt.plot([0, 1], [0, 1], 'k--')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend(loc='lower right')
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_path, 'training_history.png'))

        # Save a summary of results
        with open(os.path.join(self.model_path, 'model_summary.txt'), 'w') as f:
            f.write(f"Model trained for {len(history.history['loss'])} epochs\n")
            f.write(f"Final training loss: {history.history['loss'][-1]:.6f}\n")
            f.write(f"Final validation loss: {history.history['val_loss'][-1]:.6f}\n")
            f.write(f"Optimal threshold: {optimal_threshold:.6f}\n")
            f.write(f"ROC AUC: {roc_auc:.6f}\n\n")
            f.write("Classification Report:\n")
            f.write(classification_report(y_test, predictions))

        return autoencoder, optimal_threshold, history

    def train_multiclass_model(self, X_train, y_train, X_test, y_test, epochs=50, batch_size=32):
        """Train LSTM model for multiclass classification of attack types"""
        # Reshape data for LSTM
        X_train_reshaped, X_test_reshaped = self.reshape_for_lstm(X_train, X_test)

        logger.info(f"Training data shape after reshaping: {X_train_reshaped.shape}")

        # Build the model
        model = self.build_multiclass_model(X_train_reshaped.shape[1:])

        # Print model summary
        model.summary()

        # Set up model checkpoints
        model_checkpoint = ModelCheckpoint(
            filepath=os.path.join(self.model_path, 'lstm_multiclass.h5'),
            monitor='val_accuracy',
            save_best_only=True,
            verbose=1
        )

        # Early stopping to prevent overfitting
        early_stopping = EarlyStopping(
            monitor='val_accuracy',
            patience=10,
            restore_best_weights=True,
            verbose=1
        )

        # Start training
        logger.info("Training LSTM Multiclass Model...")
        start_time = time.time()

        history = model.fit(
            X_train_reshaped, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            callbacks=[model_checkpoint, early_stopping],
            verbose=1
        )

        training_time = time.time() - start_time
        logger.info(f"Training completed in {training_time:.2f} seconds")

        # Load the best model
        model = load_model(os.path.join(self.model_path, 'lstm_multiclass.h5'))

        # Evaluate the model
        y_pred = np.argmax(model.predict(X_test_reshaped), axis=1)

        # Print classification report
        logger.info("Classification Report:")
        logger.info(classification_report(y_test, y_pred))

        # Print confusion matrix
        conf_matrix = confusion_matrix(y_test, y_pred)
        logger.info("Confusion Matrix:")
        logger.info(conf_matrix)

        # Plot the confusion matrix
        plt.figure(figsize=(10, 8))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                    xticklabels=list(self.attack_mapping.keys()),
                    yticklabels=list(self.attack_mapping.keys()))
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.savefig(os.path.join(self.model_path, 'multiclass_confusion_matrix.png'))

        # Plot the training history
        plt.figure(figsize=(12, 4))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['loss'])
        plt.plot(history.history['val_loss'])
        plt.title('Model Loss')
        plt.ylabel('Loss')
        plt.xlabel('Epoch')
        plt.legend(['Train', 'Validation'], loc='upper right')

        plt.subplot(1, 2, 2)
        plt.plot(history.history['accuracy'])
        plt.plot(history.history['val_accuracy'])
        plt.title('Model Accuracy')
        plt.ylabel('Accuracy')
        plt.xlabel('Epoch')
        plt.legend(['Train', 'Validation'], loc='lower right')
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_path, 'multiclass_training_history.png'))

        # Save a summary of results
        with open(os.path.join(self.model_path, 'multiclass_model_summary.txt'), 'w') as f:
            f.write(f"Model trained for {len(history.history['loss'])} epochs\n")
            f.write(f"Final training loss: {history.history['loss'][-1]:.6f}\n")
            f.write(f"Final validation loss: {history.history['val_loss'][-1]:.6f}\n")
            f.write(f"Final training accuracy: {history.history['accuracy'][-1]:.6f}\n")
            f.write(f"Final validation accuracy: {history.history['val_accuracy'][-1]:.6f}\n\n")
            f.write("Classification Report:\n")
            f.write(classification_report(y_test, y_pred))

        return model, history

    def save_preprocessing_info(self, feature_cols):
        """Save preprocessing information for later use in prediction"""
        preprocessing_info = {
            'feature_cols': feature_cols,
            'categorical_encoders': self.categorical_encoders,
            'categorical_cols': self.categorical_cols,
            'numerical_cols': self.numerical_cols,
            'attack_mapping': self.attack_mapping
        }

        with open(os.path.join(self.model_path, 'preprocessing_info.pkl'), 'wb') as f:
            pickle.dump(preprocessing_info, f)


def main():
    # Set random seeds for reproducibility
    np.random.seed(42)
    tf.random.set_seed(42)

    # Create processor
    processor = NSLKDDProcessor()

    # Load data
    train_df, test_df = processor.load_data()

    # Model training settings
    epochs = 10
    batch_size = 32

    # Train autoencoder model (anomaly detection)
    logger.info("\n=== Training LSTM Autoencoder for Anomaly Detection ===")
    X_train_benign, X_test, y_test, feature_cols = processor.preprocess_data(train_df, test_df, for_autoencoder=True)
    autoencoder, threshold, ae_history = processor.train_autoencoder(
        X_train_benign, X_test, y_test, epochs=epochs, batch_size=batch_size
    )

    # Train multiclass model (attack classification)
    logger.info("\n=== Training LSTM for Multi-class Attack Classification ===")
    X_train, y_train, X_test, y_test, feature_cols = processor.preprocess_data(train_df, test_df, for_autoencoder=False)
    multiclass_model, mc_history = processor.train_multiclass_model(
        X_train, y_train, X_test, y_test, epochs=epochs, batch_size=batch_size
    )

    # Save preprocessing information for later use
    processor.save_preprocessing_info(feature_cols)

    logger.info("\nTraining complete! Models saved in the 'models' directory.")
    logger.info("You can now use these models with the cyber threat detection dashboard.")


if __name__ == "__main__":
    main()