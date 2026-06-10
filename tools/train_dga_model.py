"""
train_dga_model.py
==================
Script huấn luyện ngoại tuyến (Offline Training) cho mô hình phân loại DGA
(Domain Generation Algorithm) trong dự án DNS Exfiltration Detector.

Quy trình:
    1. Đọc dữ liệu từ `data/output/dns_queries.json`.
    2. Lọc bỏ các bản ghi có nhãn "unknown".
    3. Trích xuất và tính toán 7 đặc trưng (features) cho mỗi tên miền.
    4. Tìm siêu tham số tối ưu bằng RandomizedSearchCV trên tập con (subsampling).
    5. Huấn luyện mô hình tốt nhất trên toàn bộ tập train.
    6. Đánh giá trên tập test độc lập (không bị rò rỉ dữ liệu).
    7. Lưu mô hình đã huấn luyện vào `models/dga_model.pkl`.

Lưu ý thiết kế:
    - ``class_weight`` không cần thiết vì dataset có phân bố cân bằng tự nhiên
      (benign ≈ 56%, malicious ≈ 44%, tỉ lệ ~1.27:1).
    - Dùng ``scoring="roc_auc"`` thay vì ``accuracy`` trong CV để đo khả năng
      phân biệt 2 class thực sự, không bị ảnh hưởng bởi ngưỡng quyết định.
    - Mô hình cuối chỉ được fit trên ``X_train`` (không gộp test set) để
      đảm bảo kết quả đánh giá trên test set có giá trị thực sự.
    - Subsampling 200k mẫu chỉ áp dụng trong bước RandomizedSearchCV để tăng
      tốc tìm tham số; fit thực sự vẫn dùng toàn bộ tập train (~1.14 triệu mẫu).

Tác giả  : DNS Exfiltration Detector Team
Phiên bản: 2.1.0
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    train_test_split,
)

# ---------------------------------------------------------------------------
# Đường dẫn mặc định
# ---------------------------------------------------------------------------
ROOT_DIR: Path = Path(__file__).resolve().parent.parent
DATA_PATH: Path = ROOT_DIR / "data" / "output" / "dns_queries.json"
MODEL_DIR: Path = ROOT_DIR / "models"
MODEL_PATH: Path = MODEL_DIR / "dga_model.pkl"

VOWELS: frozenset[str] = frozenset("aeiou")

# Số mẫu tối đa dùng để tuning (subsampling) — giảm tải CPU/RAM
TUNE_LIMIT: int = 200_000

# Số tổ hợp tham số thử nghiệm trong RandomizedSearchCV
# Không gian có 4×5×3×3=180 tổ hợp → thử 30 ≈ 17% là hợp lý
N_ITER_SEARCH: int = 30


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

def compute_subdomain_features(subdomain: str) -> dict[str, float]:
    """Tính toán 4 đặc trưng thống kê từ chuỗi subdomain.

    Parameters
    ----------
    subdomain : str
        Chuỗi subdomain cần phân tích (có thể rỗng).

    Returns
    -------
    dict[str, float]
        Bốn đặc trưng: ``subdomain_length``, ``vowel_ratio``,
        ``consonant_ratio``, ``unique_char_ratio``.

    Notes
    -----
    Khi subdomain rỗng hoặc không có ký tự chữ cái, tất cả tỉ lệ
    trả về ``0.0`` để tránh lỗi chia cho không.
    """
    length: int = len(subdomain)
    if length == 0:
        return {
            "subdomain_length": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
        }

    alpha_chars: list[str] = [c for c in subdomain.lower() if c.isalpha()]
    alpha_count: int = len(alpha_chars)

    vowel_count: int = sum(1 for c in alpha_chars if c in VOWELS)
    consonant_count: int = alpha_count - vowel_count
    unique_char_count: int = len(set(subdomain.lower()))

    return {
        "subdomain_length": float(length),
        "vowel_ratio": vowel_count / alpha_count if alpha_count > 0 else 0.0,
        "consonant_ratio": consonant_count / alpha_count if alpha_count > 0 else 0.0,
        "unique_char_ratio": unique_char_count / length,
    }


def extract_features(record: dict[str, Any]) -> list[float]:
    """Trích xuất vector đặc trưng 7 chiều từ một bản ghi DNS query.

    Kết hợp 3 đặc trưng có sẵn trong JSON (``domain_length``,
    ``digit_ratio``, ``label_count``) với 4 đặc trưng tính toán từ
    ``subdomain``.

    Parameters
    ----------
    record : dict[str, Any]
        Bản ghi DNS query theo schema ``dns_queries.json``. Các trường
        ``query_id``, ``timestamp``, ``src_ip``, ``domain``, ``tld``,
        ``query_type``, ``label``, ``count``, ``source`` bị bỏ qua.

    Returns
    -------
    list[float]
        Vector 7 phần tử:
        [domain_length, digit_ratio, label_count,
         subdomain_length, vowel_ratio, consonant_ratio, unique_char_ratio]

    Raises
    ------
    KeyError
        Nếu thiếu trường ``domain_length``, ``digit_ratio`` hoặc ``label_count``.
    """
    sub: dict[str, float] = compute_subdomain_features(record.get("subdomain", ""))
    return [
        float(record["domain_length"]),
        float(record["digit_ratio"]),
        float(record["label_count"]),
        sub["subdomain_length"],
        sub["vowel_ratio"],
        sub["consonant_ratio"],
        sub["unique_char_ratio"],
    ]


# ---------------------------------------------------------------------------
# Tải & tiền xử lý dữ liệu
# ---------------------------------------------------------------------------

def load_and_preprocess(data_path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Đọc file JSON, lọc nhãn và trả về ma trận đặc trưng + nhãn.

    Schema JSON đầu vào (từ ``dns_extractor_agent``):
    Mảng các object với các trường: ``query_id``, ``timestamp``,
    ``src_ip``, ``domain``, ``query_type``, ``subdomain``, ``tld``,
    ``label_count``, ``domain_length``, ``digit_ratio``, ``label``,
    ``count``, ``source``.

    Parameters
    ----------
    data_path : Path
        Đường dẫn tới file ``dns_queries.json``.

    Returns
    -------
    tuple[np.ndarray, np.ndarray]
        ``X`` shape ``(n_samples, 7)`` và ``y`` nhãn nhị phân
        (0 = benign, 1 = malicious).

    Raises
    ------
    FileNotFoundError
        Nếu file không tồn tại.
    ValueError
        Nếu không còn bản ghi hợp lệ sau khi lọc.
    """
    if not data_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file dữ liệu: {data_path}")

    with data_path.open("r", encoding="utf-8") as f:
        records: list[dict[str, Any]] = json.load(f)

    label_map: dict[str, int] = {"benign": 0, "malicious": 1}
    X_list: list[list[float]] = []
    y_list: list[int] = []
    
    # Sử dụng set để theo dõi các tên miền đã xử lý
    seen_domains: set[tuple[str, str]] = set()
    
    skipped_unknown: int = 0
    skipped_duplicate: int = 0
    skipped_missing: int = 0

    for rec in records:
        raw_label: str = rec.get("label", "unknown")
        if raw_label not in label_map:
            skipped_unknown += 1
            continue
            
        # Lấy định danh duy nhất của query (subdomain + domain)
        domain_key = (rec.get("subdomain", ""), rec.get("domain", ""))
        
        # Kiểm tra trùng lặp
        if domain_key in seen_domains:
            skipped_duplicate += 1
            continue

        try:
            X_list.append(extract_features(rec))
            y_list.append(label_map[raw_label])
            # Đánh dấu đã xử lý tên miền này
            seen_domains.add(domain_key)
        except KeyError as e:
            print(f"[WARN] Bản ghi #{rec.get('query_id', '?')} thiếu trường: {e}")
            skipped_missing += 1

    print(f"[INFO] Tổng bản ghi ban đầu : {len(records)}")
    print(f"[INFO] Bỏ qua (unknown)     : {skipped_unknown}")
    print(f"[INFO] Bỏ qua (trùng lặp)   : {skipped_duplicate}  ← Đã lọc trùng!")
    print(f"[INFO] Bỏ qua (thiếu trường): {skipped_missing}")
    print(f"[INFO] Bản ghi hợp lệ (Unique): {len(X_list)}")

    if not X_list:
        raise ValueError("Không có bản ghi hợp lệ nào để huấn luyện.")

    X: np.ndarray = np.array(X_list, dtype=np.float64)
    y: np.ndarray = np.array(y_list, dtype=np.int32)

    benign_n = int(np.sum(y == 0))
    malicious_n = int(np.sum(y == 1))
    ratio = benign_n / malicious_n if malicious_n > 0 else float("inf")
    print(f"[INFO] Phân bố nhãn mới    : benign={benign_n}, malicious={malicious_n}")
    print(f"[INFO] Tỉ lệ imbalance     : {ratio:.2f}:1")

    return X, y


# ---------------------------------------------------------------------------
# Huấn luyện & đánh giá
# ---------------------------------------------------------------------------

def train(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.2,
    random_state: int = 42,
) -> RandomForestClassifier:
    """Tìm siêu tham số tối ưu, huấn luyện và đánh giá RandomForestClassifier.

    Chiến lược:
    1. Chia train/test với ``stratify=y`` để giữ nguyên tỉ lệ class.
    2. Subsampling tập train (tối đa ``TUNE_LIMIT`` mẫu) để tăng tốc CV.
    3. ``RandomizedSearchCV`` với ``scoring="roc_auc"`` — phù hợp hơn
       ``accuracy`` khi data mất cân bằng.
    4. Fit mô hình tốt nhất trên **toàn bộ tập train** (không gộp test).
    5. Đánh giá trên tập test độc lập → kết quả có giá trị thực sự.

    Parameters
    ----------
    X : np.ndarray
        Ma trận đặc trưng shape ``(n_samples, 7)``.
    y : np.ndarray
        Nhãn nhị phân.
    test_size : float
        Tỉ lệ tập test (mặc định 0.2).
    random_state : int
        Seed cho tính tái lập (mặc định 42).

    Returns
    -------
    RandomForestClassifier
        Mô hình đã fit trên toàn bộ tập train với siêu tham số tối ưu.

    Notes
    -----
    Dataset có phân bố cân bằng tự nhiên (benign ≈ 56%, malicious ≈ 44%)
    nên không cần ``class_weight="balanced"``. Nếu tỉ lệ thay đổi vượt
    ngưỡng 3:1 trong tương lai, cần bật lại tham số này.
    """
    # --- Bước 1: Chia train / test ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"\n[INFO] Tập train           : {X_train.shape[0]:,} mẫu")
    print(f"[INFO] Tập test            : {X_test.shape[0]:,} mẫu")

    # --- Bước 2: Subsampling để tăng tốc tuning ---
    if len(X_train) > TUNE_LIMIT:
        print(f"\n[INFO] Subsampling {TUNE_LIMIT:,} mẫu để tuning (tránh quá tải CPU)...")
        X_tune, _, y_tune, _ = train_test_split(
            X_train, y_train,
            train_size=TUNE_LIMIT,
            stratify=y_train,
            random_state=random_state,
        )
    else:
        X_tune, y_tune = X_train, y_train
    print(f"[INFO] Mẫu dùng để tuning  : {len(X_tune):,}")

    # --- Bước 3: RandomizedSearchCV ---
    # Dataset có phân bố cân bằng tự nhiên (benign≈56%, malicious≈44%)
    # nên không cần class_weight. Các tham số cần tune là cấu trúc cây.
    base_clf = RandomForestClassifier(
        random_state=random_state,
        n_jobs=-1,
    )

    param_dist: dict[str, list] = {
        "n_estimators":      [100, 150, 200, 300],
        "max_depth":         [10, 15, 20, 25, None],
        "min_samples_split": [5, 10, 15],
        "min_samples_leaf":  [1, 2, 4],
    }

    cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)

    print(f"\n[INFO] Bắt đầu RandomizedSearchCV ({N_ITER_SEARCH} tổ hợp × 5-Fold)...")
    print("       scoring=roc_auc — đo khả năng phân biệt 2 class thực sự")

    random_search = RandomizedSearchCV(
        estimator=base_clf,
        param_distributions=param_dist,
        n_iter=N_ITER_SEARCH,
        cv=cv_strategy,
        scoring="roc_auc",     # ← đổi từ accuracy sang roc_auc
        n_jobs=-1,
        verbose=1,
        random_state=random_state,
        refit=True,
    )
    random_search.fit(X_tune, y_tune)

    print(f"\n[INFO] Siêu tham số tốt nhất : {random_search.best_params_}")
    print(f"[INFO] ROC-AUC trên CV       : {random_search.best_score_:.4f}")

    # --- Bước 4: Fit lại trên toàn bộ tập TRAIN (không gộp test) ---
    # Lý do: kết quả đánh giá ở bước 5 chỉ có giá trị nếu test set
    # hoàn toàn độc lập, chưa từng được model "nhìn thấy".
    print("\n[INFO] Fit mô hình tốt nhất trên toàn bộ tập train...")
    best_clf: RandomForestClassifier = random_search.best_estimator_
    best_clf.fit(X_train, y_train)

    # --- Bước 5: Đánh giá trên tập test độc lập ---
    y_pred: np.ndarray = best_clf.predict(X_test)
    y_proba: np.ndarray = best_clf.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 58)
    print("            KẾT QUẢ ĐÁNH GIÁ MÔ HÌNH TỐI ƯU")
    print("=" * 58)
    print(f"  Accuracy            : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  ROC-AUC             : {roc_auc_score(y_test, y_proba):.4f}")
    print("-" * 58)
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
    print("=" * 58)

    feature_names: list[str] = [
        "domain_length", "digit_ratio", "label_count",
        "subdomain_length", "vowel_ratio", "consonant_ratio", "unique_char_ratio",
    ]
    print("\n  Feature Importance (giảm dần):")
    for name, imp in sorted(
        zip(feature_names, best_clf.feature_importances_), key=lambda x: -x[1]
    ):
        bar = "█" * int(imp * 40)
        print(f"  {name:<22} {imp:.4f}  {bar}")
    print()

    return best_clf


# ---------------------------------------------------------------------------
# Lưu mô hình
# ---------------------------------------------------------------------------

def save_model(clf: RandomForestClassifier, model_path: Path) -> None:
    """Lưu mô hình đã huấn luyện vào file .pkl bằng joblib.

    Parameters
    ----------
    clf : RandomForestClassifier
        Mô hình cần lưu.
    model_path : Path
        Đường dẫn đích. Thư mục cha được tạo tự động nếu chưa tồn tại.
    """
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"[INFO] Mô hình đã được lưu tại: {model_path}")


# ---------------------------------------------------------------------------
# Pipeline chính
# ---------------------------------------------------------------------------

def run_training_pipeline(
    data_path: Path = DATA_PATH,
    model_path: Path = MODEL_PATH,
) -> None:
    """Chạy toàn bộ pipeline: load → preprocess → tune → train → evaluate → save.

    Parameters
    ----------
    data_path : Path
        Đường dẫn file JSON đầu vào.
    model_path : Path
        Đường dẫn lưu file .pkl đầu ra.
    """
    print("=" * 58)
    print("    DGA MODEL — OFFLINE TRAINING PIPELINE v2.0")
    print("=" * 58)

    print(f"\n[STEP 1] Tải và tiền xử lý dữ liệu...\n         {data_path}\n")
    X, y = load_and_preprocess(data_path)

    print("\n[STEP 2] Tuning + Huấn luyện...")
    clf = train(X, y)

    print("\n[STEP 3] Lưu mô hình...")
    save_model(clf, model_path)

    print("\n[DONE] Pipeline hoàn tất.\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    custom_data = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_PATH
    custom_model = Path(sys.argv[2]) if len(sys.argv) > 2 else MODEL_PATH
    run_training_pipeline(data_path=custom_data, model_path=custom_model)