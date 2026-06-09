"""
train_dga_model.py
==================
Script huấn luyện ngoại tuyến (Offline Training) cho mô hình phân loại DGA
(Domain Generation Algorithm) trong dự án DNS Exfiltration Detector.

Quy trình:
    1. Đọc dữ liệu từ `data/output/dns_queries.json`.
    2. Lọc bỏ các bản ghi có nhãn "unknown".
    3. Trích xuất và tính toán 7 đặc trưng (features) cho mỗi tên miền.
    4. Huấn luyện mô hình RandomForestClassifier.
    5. Đánh giá mô hình và in kết quả ra console.
    6. Lưu mô hình đã huấn luyện vào `models/dga_model.pkl`.

"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, auc, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------------------
# Đường dẫn mặc định (có thể ghi đè khi gọi từ module khác)
# ---------------------------------------------------------------------------
ROOT_DIR: Path = Path(__file__).resolve().parent.parent
DATA_PATH: Path = ROOT_DIR / "data" / "output" / "dns_queries.json"
MODEL_DIR: Path = ROOT_DIR / "models"
MODEL_PATH: Path = MODEL_DIR / "dga_model.pkl"

# Tập ký tự nguyên âm tiếng Anh (dùng cho feature engineering)
VOWELS: frozenset[str] = frozenset("aeiou")


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

def compute_subdomain_features(subdomain: str) -> dict[str, float]:
    """Tính toán 4 đặc trưng bổ sung từ chuỗi subdomain.

    Các đặc trưng được tính dựa trên phân tích thống kê ký tự trong subdomain,
    giúp mô hình phân biệt các tên miền do DGA sinh ra (thường có cấu trúc
    ngẫu nhiên, nhiều phụ âm liên tiếp) với tên miền hợp lệ (có từ có nghĩa).

    Parameters
    ----------
    subdomain : str
        Chuỗi subdomain cần phân tích (ví dụ: "mail", "xkcd2z9q", "").

    Returns
    -------
    dict[str, float]
        Từ điển chứa 4 đặc trưng:
        - ``subdomain_length``  : Độ dài chuỗi subdomain (int được trả về
          dưới dạng float để thống nhất kiểu dữ liệu).
        - ``vowel_ratio``       : Tỉ lệ ký tự nguyên âm (a,e,i,o,u) trên
          tổng số ký tự chữ cái.
        - ``consonant_ratio``   : Tỉ lệ ký tự phụ âm trên tổng số ký tự
          chữ cái.
        - ``unique_char_ratio`` : Tỉ lệ số ký tự không trùng lặp trên tổng
          độ dài chuỗi subdomain. Giá trị cao cho thấy tính ngẫu nhiên cao.

    Notes
    -----
    Trường hợp subdomain rỗng hoặc không chứa ký tự chữ cái, tất cả tỉ lệ
    được đặt về ``0.0`` để tránh lỗi chia cho 0.
    """
    length: int = len(subdomain)
    if length == 0:
        return {
            "subdomain_length": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
        }

    # Chỉ xét ký tự chữ cái (loại bỏ số và ký tự đặc biệt như dấu chấm, gạch ngang)
    alpha_chars: list[str] = [c for c in subdomain.lower() if c.isalpha()]
    alpha_count: int = len(alpha_chars)

    vowel_count: int = sum(1 for c in alpha_chars if c in VOWELS)
    consonant_count: int = alpha_count - vowel_count
    unique_char_count: int = len(set(subdomain.lower()))

    vowel_ratio: float = vowel_count / alpha_count if alpha_count > 0 else 0.0
    consonant_ratio: float = consonant_count / alpha_count if alpha_count > 0 else 0.0
    unique_char_ratio: float = unique_char_count / length

    return {
        "subdomain_length": float(length),
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "unique_char_ratio": unique_char_ratio,
    }


def extract_features(record: dict[str, Any]) -> list[float]:
    """Trích xuất vector đặc trưng từ một bản ghi DNS query.

    Kết hợp 3 đặc trưng có sẵn trong JSON với 4 đặc trưng được tính toán
    từ trường ``subdomain`` để tạo thành vector đặc trưng 7 chiều.

    Parameters
    ----------
    record : dict[str, Any]
        Một object JSON đại diện cho một DNS query theo schema dns_queries.json,
        phải chứa các trường: ``domain_length``, ``digit_ratio``, ``label_count``,
        ``subdomain``. Các trường khác (query_id, timestamp, src_ip, domain, 
        query_type, tld, label, count, source) sẽ được bỏ qua.

    Returns
    -------
    list[float]
        Vector đặc trưng gồm 7 phần tử theo thứ tự:
        [domain_length, digit_ratio, label_count,
         subdomain_length, vowel_ratio, consonant_ratio, unique_char_ratio]

    Raises
    ------
    KeyError
        Nếu thiếu các trường bắt buộc (domain_length, digit_ratio, label_count, subdomain).
    """
    subdomain_feats: dict[str, float] = compute_subdomain_features(
        record.get("subdomain", "")
    )
    return [
        float(record["domain_length"]),
        float(record["digit_ratio"]),
        float(record["label_count"]),
        subdomain_feats["subdomain_length"],
        subdomain_feats["vowel_ratio"],
        subdomain_feats["consonant_ratio"],
        subdomain_feats["unique_char_ratio"],
    ]


# ---------------------------------------------------------------------------
# Tải & tiền xử lý dữ liệu
# ---------------------------------------------------------------------------

def load_and_preprocess(data_path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Đọc file JSON dns_queries.json, lọc nhãn và chuyển đổi thành ma trận đặc trưng + nhãn.

    Định dạng JSON đầu vào (schema từ dns_extractor_agent):
    - Mảng JSON chứa các object, mỗi object có các trường:
      query_id, timestamp, src_ip, domain, query_type, subdomain, tld,
      label_count, domain_length, digit_ratio, label, count, source
    - Chỉ các trường sau được sử dụng để trích xuất đặc trưng:
      domain_length, digit_ratio, label_count, subdomain, label

    Parameters
    ----------
    data_path : Path
        Đường dẫn tuyệt đối tới file ``dns_queries.json``.

    Returns
    -------
    tuple[np.ndarray, np.ndarray]
        - ``X`` : Ma trận đặc trưng có shape ``(n_samples, 7)``.
        - ``y`` : Mảng nhãn nhị phân (0 = benign, 1 = malicious).

    Raises
    ------
    FileNotFoundError
        Nếu file JSON không tồn tại tại ``data_path``.
    ValueError
        Nếu không còn bản ghi hợp lệ nào sau khi lọc nhãn "unknown".
    """
    if not data_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file dữ liệu: {data_path}")

    with data_path.open("r", encoding="utf-8") as f:
        records: list[dict[str, Any]] = json.load(f)

    label_map: dict[str, int] = {"benign": 0, "malicious": 1}

    X_list: list[list[float]] = []
    y_list: list[int] = []
    skipped: int = 0

    for rec in records:
        raw_label: str = rec.get("label", "unknown")
        if raw_label not in label_map:
            # Bỏ qua các bản ghi có nhãn "unknown" hoặc nhãn không hợp lệ
            skipped += 1
            continue
        try:
            X_list.append(extract_features(rec))
            y_list.append(label_map[raw_label])
        except KeyError as e:
            # Ghi log và bỏ qua nếu thiếu trường bắt buộc
            print(f"[WARN] Bản ghi #{rec.get('query_id', '?')} thiếu trường: {e}")
            skipped += 1
            continue

    print(f"[INFO] Tổng bản ghi        : {len(records)}")
    print(f"[INFO] Bỏ qua (unknown)    : {skipped}")
    print(f"[INFO] Bản ghi hợp lệ      : {len(X_list)}")

    if len(X_list) == 0:
        raise ValueError("Không có bản ghi hợp lệ nào để huấn luyện.")

    X: np.ndarray = np.array(X_list, dtype=np.float64)
    y: np.ndarray = np.array(y_list, dtype=np.int32)

    benign_count: int = int(np.sum(y == 0))
    malicious_count: int = int(np.sum(y == 1))
    print(f"[INFO] Phân bố nhãn        : benign={benign_count}, malicious={malicious_count}")

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
    """Huấn luyện RandomForestClassifier và in kết quả đánh giá ra console.

    Dữ liệu được chia theo tỉ lệ ``(1 - test_size) : test_size`` cho tập
    huấn luyện và tập kiểm tra. Kết quả đánh giá bao gồm Accuracy tổng thể
    và Classification Report chi tiết (Precision, Recall, F1-score).

    Parameters
    ----------
    X : np.ndarray
        Ma trận đặc trưng đầu vào, shape ``(n_samples, n_features)``.
    y : np.ndarray
        Mảng nhãn nhị phân tương ứng.
    test_size : float, optional
        Tỉ lệ dữ liệu dành cho tập kiểm tra (mặc định ``0.2`` = 20%).
    random_state : int, optional
        Hạt giống ngẫu nhiên để đảm bảo tính tái lập (mặc định ``42``).

    Returns
    -------
    RandomForestClassifier
        Mô hình đã được huấn luyện trên toàn bộ tập dữ liệu.

    Notes
    -----
    Mô hình cuối cùng được ``fit`` lại trên **toàn bộ** tập dữ liệu
    (không chỉ tập train) để tối đa hoá thông tin học được trước khi
    lưu ra file, trong khi đánh giá vẫn thực hiện trên tập test riêng.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"\n[INFO] Kích thước tập train : {X_train.shape[0]} mẫu")
    print(f"[INFO] Kích thước tập test  : {X_test.shape[0]} mẫu")

    # Khởi tạo và huấn luyện mô hình trên tập train
    clf: RandomForestClassifier = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # --- Đánh giá trên tập test ---
    y_pred: np.ndarray = clf.predict(X_test)
    accuracy: float = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 55)
    print("           KẾT QUẢ ĐÁNH GIÁ MÔ HÌNH")
    print("=" * 55)
    print(f"  Accuracy : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print("-" * 55)
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
    print("=" * 55)

    y_proba = clf.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    print(f"  ROC-AUC  : {auc:.4f}")
    # Feature importance
    feature_names: list[str] = [
        "domain_length", "digit_ratio", "label_count",
        "subdomain_length", "vowel_ratio", "consonant_ratio", "unique_char_ratio",
    ]
    importances: np.ndarray = clf.feature_importances_
    print("\n  Feature Importance (giảm dần):")
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        bar: str = "█" * int(imp * 40)
        print(f"  {name:<22} {imp:.4f}  {bar}")
    print()

    # Fit lại mô hình trên toàn bộ dữ liệu trước khi lưu
    clf.fit(X, y)
    return clf


# ---------------------------------------------------------------------------
# Lưu mô hình
# ---------------------------------------------------------------------------

def save_model(clf: RandomForestClassifier, model_path: Path) -> None:
    """Lưu mô hình đã huấn luyện vào file nhị phân bằng joblib.

    Parameters
    ----------
    clf : RandomForestClassifier
        Đối tượng mô hình đã huấn luyện cần lưu.
    model_path : Path
        Đường dẫn đích để lưu file ``.pkl``.

    Notes
    -----
    Thư mục cha của ``model_path`` sẽ được tạo tự động nếu chưa tồn tại.
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
    """Chạy toàn bộ pipeline huấn luyện từ đầu đến cuối.

    Bao gồm: tải dữ liệu → tiền xử lý → huấn luyện → đánh giá → lưu mô hình.

    Parameters
    ----------
    data_path : Path, optional
        Đường dẫn tới file dữ liệu JSON đầu vào.
    model_path : Path, optional
        Đường dẫn lưu mô hình đầu ra.
    """
    print("=" * 55)
    print("      DGA MODEL — OFFLINE TRAINING PIPELINE")
    print("=" * 55)

    print(f"\n[STEP 1] Tải và tiền xử lý dữ liệu từ:\n         {data_path}\n")
    X, y = load_and_preprocess(data_path)

    print("\n[STEP 2] Huấn luyện RandomForestClassifier...")
    clf = train(X, y)

    print("\n[STEP 3] Lưu mô hình...")
    save_model(clf, model_path)

    print("\n[DONE] Pipeline hoàn tất.\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Cho phép ghi đè đường dẫn qua tham số dòng lệnh (tuỳ chọn)
    custom_data = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_PATH
    custom_model = Path(sys.argv[2]) if len(sys.argv) > 2 else MODEL_PATH
    run_training_pipeline(data_path=custom_data, model_path=custom_model)