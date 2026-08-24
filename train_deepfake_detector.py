import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

def generate_synthetic_audio_dataset(num_samples=100, features_shape=(40, 174)):
    """تجميع وتوليد مجموعة بيانات صوتية مصغرة (Datasets) للأصوات الحقيقية والمزيفة"""
    np.random.seed(42)
    X = []
    y = []
    
    # 0 = Real Audio, 1 = Deepfake Audio
    for _ in range(num_samples // 2):
        # الأصوات الحقيقية تحوي أنماط تردد طبيعية
        real_feature = np.random.normal(loc=0.5, scale=0.1, size=features_shape).flatten()
        X.append(real_feature)
        y.append(0)
        
        # الأصوات المزيفة تحوي تشويشاً وأنماطاً اصطناعية
        fake_feature = np.random.normal(loc=0.8, scale=0.2, size=features_shape).flatten()
        X.append(fake_feature)
        y.append(1)
        
    return np.array(X), np.array(y)

def train_and_evaluate():
    print("1. جاري تحميل وتجميع مجموعة البيانات (Datasets)...")
    X, y = generate_synthetic_audio_dataset(num_samples=200)
    
    # تقسيم البيانات للتدريب والتقييم
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("2. تدريب نموذج التمييز (Binary Classifier)...")
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    print("3. تقييم دقة النموذج (Evaluation Metrics)...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    
    print(f" -> Accuracy  (الدقة): {acc * 100:.2f}%")
    print(f" -> Precision (الضبط): {prec * 100:.2f}%")
    print(f" -> Recall    (الاستدعاء): {rec * 100:.2f}%")
    
    print("4. حفظ أوزان النموذج (Model Weights)...")
    joblib.dump(model, "deepfake_model.pkl")
    print("تم حفظ النموذج بنجاح في ملف 'deepfake_model.pkl'!")

if __name__ == "__main__":
    train_and_evaluate()