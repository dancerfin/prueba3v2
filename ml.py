from __future__ import division
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.utils import class_weight
from sklearn.pipeline import make_pipeline
import joblib
from collections import deque
import time
import statistics
import warnings

warnings.filterwarnings('ignore', category=UserWarning)

class HybridDDoSDetector:
    def __init__(self):
        self.rf_model = None
        self.svm_model = None
        self.scaler = None
        self.last_predictions = deque(maxlen=20)
        self.prediction_history = deque(maxlen=100)
        self.attack_prob_history = deque(maxlen=100)
        self.dynamic_threshold = 0.4  # Umbral inicial más bajo
        self.last_update_time = time.time()
        
        # Configuración optimizada de modelos
        self.rf_params = {
            'n_estimators': 200,
            'max_depth': 15,
            'min_samples_split': 2,
            'class_weight': 'balanced_subsample',
            'random_state': 42
        }
        
        self.svm_params = {
            'kernel': 'rbf',
            'C': 2.0,
            'gamma': 'auto',
            'probability': True,
            'class_weight': 'balanced',
            'cache_size': 1000
        }
        
        try:
            self.load_models()
            print("Modelos híbridos cargados exitosamente")
        except Exception as e:
            print(f"Error al cargar modelos: {str(e)}. Entrenando nuevos modelos...")
            self.train_hybrid_model()
    
    def load_models(self):
        """Carga los modelos y el scaler desde archivos"""
        self.rf_model = joblib.load('rf_model.pkl')
        self.svm_model = joblib.load('svm_model.pkl')
        self.scaler = joblib.load('scaler.pkl')
    
    def save_models(self):
        """Guarda los modelos entrenados y el scaler"""
        joblib.dump(self.rf_model, 'rf_model.pkl')
        joblib.dump(self.svm_model, 'svm_model.pkl')
        joblib.dump(self.scaler, 'scaler.pkl')
    
    def calculate_class_weights(self, y):
        """Calcula pesos de clases para manejar desbalance"""
        classes = np.unique(y)
        weights = class_weight.compute_class_weight('balanced', classes=classes, y=y)
        return dict(zip(classes, weights))
    
    def train_hybrid_model(self):
        """Entrena ambos modelos con los datos de result.csv"""
        # Cargar y preparar datos
        data = np.loadtxt(open('result.csv', 'rb'), delimiter=',', dtype='str')
        X = data[:, 0:5].astype(float)
        y = data[:, 5]
        
        # Verificar balance de clases
        unique, counts = np.unique(y, return_counts=True)
        print("\nDistribución de clases:", dict(zip(unique, counts)))
        
        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Normalización de características
        self.scaler = StandardScaler()
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)
        
        # Calcular pesos de clases
        class_weights = self.calculate_class_weights(y_train)
        self.rf_params['class_weight'] = class_weights
        self.svm_params['class_weight'] = class_weights
        
        # Entrenar Random Forest con búsqueda de hiperparámetros
        print("\nOptimizando Random Forest...")
        rf_grid = {
            'n_estimators': [200, 300],
            'max_depth': [15, 20, None],
            'min_samples_split': [2, 5]
        }
        rf_cv = GridSearchCV(RandomForestClassifier(**self.rf_params), rf_grid, cv=3, n_jobs=-1)
        rf_cv.fit(X_train, y_train)
        self.rf_model = rf_cv.best_estimator_
        print(f"Mejores parámetros RF: {rf_cv.best_params_}")
        
        # Entrenar SVM con búsqueda de hiperparámetros
        print("\nOptimizando SVM...")
        svm_grid = {
            'C': [1.0, 1.5, 2.0],
            'gamma': ['scale', 'auto']
        }
        svm_cv = GridSearchCV(svm.SVC(**self.svm_params), svm_grid, cv=3, n_jobs=-1)
        svm_cv.fit(X_train, y_train)
        self.svm_model = svm_cv.best_estimator_
        print(f"Mejores parámetros SVM: {svm_cv.best_params_}")
        
        # Evaluar modelos
        print("\nEvaluación Random Forest:")
        y_pred_rf = self.rf_model.predict(X_test)
        print(classification_report(y_test, y_pred_rf))
        print("Matriz de confusión:")
        print(confusion_matrix(y_test, y_pred_rf))
        
        print("\nEvaluación SVM:")
        y_pred_svm = self.svm_model.predict(X_test)
        print(classification_report(y_test, y_pred_svm))
        print("Matriz de confusión:")
        print(confusion_matrix(y_test, y_pred_svm))
        
        # Calcular umbral inicial basado en los datos de entrenamiento
        self._calculate_initial_threshold(X_train, y_train)
        
        # Guardar modelos
        self.save_models()
    
    def _calculate_initial_threshold(self, X, y):
        """Calcula umbral inicial basado en probabilidades de entrenamiento"""
        rf_proba = self.rf_model.predict_proba(X)[:, 1]
        svm_proba = self.svm_model.predict_proba(X)[:, 1]
        combined_proba = (rf_proba + svm_proba) / 2
        self.dynamic_threshold = np.percentile(combined_proba[y == '1'], 15)  # Percentil más bajo
    
    def _update_dynamic_threshold(self):
        """Actualiza el umbral dinámico basado en el historial"""
        if len(self.attack_prob_history) > 20:
            recent_probs = list(self.attack_prob_history)[-20:]
            mean_prob = statistics.mean(recent_probs)
            std_prob = statistics.stdev(recent_probs) if len(recent_probs) > 1 else 0
            
            # Ajustar umbral más agresivamente para ataques
            self.dynamic_threshold = max(0.4, min(0.8, mean_prob + std_prob * 0.3))
            
            # Actualizar solo cada 5 minutos
            current_time = time.time()
            if current_time - self.last_update_time > 300:
                self.last_update_time = current_time
                print(f"Umbral dinámico actualizado: {self.dynamic_threshold:.2f}")
    
    def hybrid_predict(self, features):
        try:
            # Convertir a array numpy y normalizar
            features = np.array(features).reshape(1, -1).astype(float)
            if self.scaler:
                features = self.scaler.transform(features)
            
            # Obtener probabilidades
            rf_proba = self.rf_model.predict_proba(features)[0]
            svm_proba = self.svm_model.predict_proba(features)[0]
            
            # Obtener clases y confianzas
            rf_class = self.rf_model.classes_[np.argmax(rf_proba)]
            rf_confidence = np.max(rf_proba)
            rf_attack_prob = rf_proba[1] if '1' in self.rf_model.classes_ else 0
            
            svm_class = self.svm_model.classes_[np.argmax(svm_proba)]
            svm_confidence = np.max(svm_proba)
            svm_attack_prob = svm_proba[1] if '1' in self.svm_model.classes_ else 0
            
            # Calcular probabilidad combinada ponderada
            combined_prob = (rf_attack_prob * 0.6 + svm_attack_prob * 0.4)
            self.attack_prob_history.append(combined_prob)
            
            # Actualizar umbral dinámico
            self._update_dynamic_threshold()
            
            # Motor de decisión mejorado
            final_pred = self._improved_decision_engine(
                rf_class, rf_confidence, rf_attack_prob,
                svm_class, svm_confidence, svm_attack_prob,
                combined_prob
            )
            
            # Guardar predicción para seguimiento temporal
            self.last_predictions.append(final_pred)
            self.prediction_history.append(final_pred)
            
            # Sistema de votación temporal más estricto
            if len(self.last_predictions) >= 10:
                recent_attacks = list(self.last_predictions).count('1')
                if recent_attacks >= 7:  # 70% de las últimas predicciones son ataques
                    final_pred = '1'
                elif recent_attacks <= 1:  # Menos del 10% son ataques
                    final_pred = '0'
            
            return [final_pred]
            
        except Exception as e:
            print(f"Error en predicción híbrida: {str(e)}")
            if len(self.prediction_history) > 0:
                fallback = statistics.mode(self.prediction_history)
                return [fallback]
            return ['0']  # Por defecto asume tráfico normal
    
    def _improved_decision_engine(self, rf_class, rf_conf, rf_attack, 
                                svm_class, svm_conf, svm_attack, combined_prob):
        """
        Motor de decisión mejorado:
        1. Mayor peso a la detección de ataques cuando hay alta probabilidad
        2. Requerir mayor concordancia entre modelos para tráfico normal
        """
        # Definir umbrales ajustados
        high_conf = 0.9
        low_conf = 0.5
        conf_diff = 0.25
        
        # Caso 1: Ambos muy seguros y coinciden
        if (rf_conf > high_conf and svm_conf > high_conf and 
            rf_class == svm_class):
            return rf_class
        
        # Caso 2: Un modelo mucho más seguro que el otro
        if rf_conf > svm_conf + conf_diff:
            return rf_class
        elif svm_conf > rf_conf + conf_diff:
            return svm_class
        
        # Caso 3: Ambos inseguros pero alta probabilidad combinada
        if rf_conf < low_conf and svm_conf < low_conf:
            return '1' if combined_prob > self.dynamic_threshold * 0.9 else '0'
        
        # Caso 4: Discordancia pero alta probabilidad de ataque
        if combined_prob > self.dynamic_threshold * 1.2:
            return '1'
        
        # Caso por defecto: usar probabilidad combinada con umbral dinámico
        return '1' if combined_prob > self.dynamic_threshold else '0'

class MachineLearningAlgo:
    """Wrapper para compatibilidad"""
    def __init__(self):
        self.detector = HybridDDoSDetector()
    
    def classify(self, data):
        return self.detector.hybrid_predict(data)