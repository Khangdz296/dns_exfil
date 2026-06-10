"""
dga_model.py
============
Tool vận hành (Inference Tool) cho ``dga_classifier_agent`` trong dự án
DNS Exfiltration Detector.

Mô-đun này cung cấp hàm ``score_dga`` để chấm điểm nguy cơ DGA cho một
danh sách các DNS query, dựa trên mô hình RandomForest đã được huấn luyện
ngoại tuyến bởi ``tools/train_dga_model.py``.

Quy trình hoạt động:
    1. Tải mô hình từ file ``models/dga_model.pkl`` (lazy-load, cache lại
       sau lần đầu tiên để tối ưu hiệu suất trong môi trường agent).
    2. Với mỗi DNS query trong danh sách đầu vào, áp dụng cùng bước
       Feature Engineering như lúc training (7 đặc trưng).
    3. Dùng ``predict_proba()`` để lấy xác suất nhãn ``malicious``.
    4. Ghi giá trị xác suất vào key ``dga_score`` của từng bản ghi.
    5. Trả về danh sách đã được cập nhật — **không ghi đè file JSON**.

Tác giả  : DNS Exfiltration Detector Team
Phiên bản: 1.0.0
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# ---------------------------------------------------------------------------
# Đường dẫn mặc định
# ---------------------------------------------------------------------------
ROOT_DIR: Path = Path(__file__).resolve().parent.parent
MODEL_PATH: Path = ROOT_DIR / "models" / "dga_model.pkl"

# Tập ký tự nguyên âm (phải nhất quán với file training)
VOWELS: frozenset[str] = frozenset("aeiou")

# Cache mô hình trong bộ nhớ để tránh tải lại nhiều lần khi agent gọi
# liên tiếp trong cùng một phiên làm việc.
_MODEL_CACHE: dict[str, RandomForestClassifier] = {}


# ---------------------------------------------------------------------------
# Feature Engineering (nhất quán 100% với train_dga_model.py)
# ---------------------------------------------------------------------------

def _compute_subdomain_features(subdomain: str) -> dict[str, float]:
    """Tính 4 đặc trưng thống kê từ chuỗi subdomain.

    Đây là bản sao chính xác của hàm cùng tên trong ``train_dga_model.py``
    nhằm đảm bảo tính nhất quán tuyệt đối giữa giai đoạn huấn luyện và
    suy luận (training-serving parity).

    Parameters
    ----------
    subdomain : str
        Chuỗi subdomain cần phân tích (có thể rỗng).

    Returns
    -------
    dict[str, float]
        Từ điển gồm 4 khoá:
        ``subdomain_length``, ``vowel_ratio``,
        ``consonant_ratio``, ``unique_char_ratio``.
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


def _extract_features(record: dict[str, Any]) -> list[float]:
    """Trích xuất vector đặc trưng 7 chiều từ một bản ghi DNS query.

    Thứ tự và cách tính hoàn toàn giống với hàm tương ứng trong script
    huấn luyện để đảm bảo mô hình nhận đúng định dạng đầu vào.

    Parameters
    ----------
    record : dict[str, Any]
        Bản ghi DNS query chứa ít nhất các trường:
        ``domain_length``, ``digit_ratio``, ``label_count``, ``subdomain``.

    Returns
    -------
    list[float]
        Vector đặc trưng 7 phần tử:
        [domain_length, digit_ratio, label_count,
         subdomain_length, vowel_ratio, consonant_ratio, unique_char_ratio]
    """
    sub_feats: dict[str, float] = _compute_subdomain_features(
        record.get("subdomain", "")
    )
    return [
        float(record.get("domain_length", 0)),
        float(record.get("digit_ratio", 0.0)),
        float(record.get("label_count", 0)),
        sub_feats["subdomain_length"],
        sub_feats["vowel_ratio"],
        sub_feats["consonant_ratio"],
        sub_feats["unique_char_ratio"],
    ]


# ---------------------------------------------------------------------------
# Tải mô hình (lazy-load với cache)
# ---------------------------------------------------------------------------

def _load_model(model_path: Path = MODEL_PATH) -> RandomForestClassifier:
    """Tải mô hình từ file .pkl, sử dụng cache nội bộ để tối ưu hiệu suất.

    Mô hình chỉ được đọc từ đĩa một lần duy nhất trong suốt vòng đời
    của tiến trình. Các lần gọi tiếp theo sẽ trả về đối tượng từ cache.

    Parameters
    ----------
    model_path : Path, optional
        Đường dẫn tới file ``dga_model.pkl``.

    Returns
    -------
    RandomForestClassifier
        Đối tượng mô hình đã được tải vào bộ nhớ.

    Raises
    ------
    FileNotFoundError
        Nếu file mô hình không tồn tại. Cần chạy ``train_dga_model.py``
        trước để sinh ra file này.
    """
    cache_key: str = str(model_path)
    if cache_key not in _MODEL_CACHE:
        if not model_path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy file mô hình: {model_path}\n"
                "Vui lòng chạy `tools/train_dga_model.py` để huấn luyện "
                "và tạo file mô hình trước."
            )
        _MODEL_CACHE[cache_key] = joblib.load(model_path)
    return _MODEL_CACHE[cache_key]


# ---------------------------------------------------------------------------
# Hàm chấm điểm chính (Public API)
# ---------------------------------------------------------------------------

def score_dga(
    queries: list[dict[str, Any]],
    model_path: Path = MODEL_PATH,
) -> list[dict[str, Any]]:
    """Chấm điểm nguy cơ DGA cho danh sách các DNS query.

    Đây là hàm Public API chính của mô-đun, được ``dga_classifier_agent``
    gọi trong quy trình phát hiện DNS Exfiltration.

    Với mỗi DNS query, hàm tính toán ``dga_score`` — xác suất mà tên miền
    đó được sinh ra bởi thuật toán DGA (Domain Generation Algorithm).
    Giá trị càng gần 1.0 thì nguy cơ càng cao.

    Parameters
    ----------
    queries : list[dict[str, Any]]
        Danh sách các bản ghi DNS query. Mỗi bản ghi là một ``dict``
        có cấu trúc chuẩn của dự án, ví dụ::

            {
                "query_id": 1,
                "timestamp": 0.0,
                "src_ip": "10.0.0.5",
                "domain": "a3f9bc12.evil.com",
                "query_type": "A",
                "subdomain": "a3f9bc12",
                "tld": "com",
                "label_count": 3,
                "domain_length": 18,
                "digit_ratio": 0.625,
                "label": "malicious",
                "count": 1,
                "source": "pcap"
            }

        Các trường ``count`` và ``source`` có mặt trong schema nhưng
        **không được sử dụng** cho feature extraction (xem ``_extract_features``).

    model_path : Path, optional
        Đường dẫn tới file mô hình ``.pkl``. Mặc định trỏ tới
        ``models/dga_model.pkl`` tính từ thư mục gốc dự án.

    Returns
    -------
    list[dict[str, Any]]
        Danh sách bản ghi **mới** (deep copy), mỗi bản ghi được bổ sung
        key ``dga_score`` kiểu ``float`` trong khoảng ``[0.0, 1.0]``.

        Ví dụ bản ghi sau khi chấm điểm::

            {
                ...,
                "dga_score": 0.87
            }

    Raises
    ------
    FileNotFoundError
        Nếu file mô hình chưa được tạo.
    ValueError
        Nếu ``queries`` là danh sách rỗng.

    Notes
    -----
    - Hàm **không** sửa đổi các dict trong danh sách đầu vào gốc
      (sử dụng ``copy.deepcopy`` nội bộ).
    - Hàm **không** ghi bất kỳ dữ liệu nào ra file. Việc lưu trữ
      kết quả là trách nhiệm của Orchestrator Agent.
    - Batch inference được thực hiện qua một lần gọi ``predict_proba``
      duy nhất để tối ưu hiệu suất thay vì gọi từng bản ghi riêng lẻ.
    """
    if not queries:
        raise ValueError("Danh sách `queries` không được rỗng.")

    model: RandomForestClassifier = _load_model(model_path)

    # Deep copy để bảo toàn dữ liệu gốc
    results: list[dict[str, Any]] = copy.deepcopy(queries)

    # Xây dựng ma trận đặc trưng (batch) — hiệu quả hơn vòng lặp predict
    feature_matrix: np.ndarray = np.array(
        [_extract_features(rec) for rec in results],
        dtype=np.float64,
    )

    # predict_proba trả về ma trận shape (n_samples, 2)
    # Cột 0: xác suất benign, Cột 1: xác suất malicious
    proba_matrix: np.ndarray = model.predict_proba(feature_matrix)
    malicious_scores: np.ndarray = proba_matrix[:, 1]

    # Ghi dga_score vào từng bản ghi kết quả
    for rec, score in zip(results, malicious_scores):
        rec["dga_score"] = round(float(score), 6)

    return results


# ---------------------------------------------------------------------------
# Entry point — chạy test độc lập
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Chạy test nhanh với dữ liệu mẫu cứng (không cần file JSON).
    Mục đích: kiểm tra pipeline inference end-to-end sau khi đã có
    file mô hình từ bước huấn luyện.

    Cách chạy:
        python tools/dga_model.py
        python tools/dga_model.py /path/to/custom_model.pkl
    """
    SAMPLE_QUERIES: list[dict[str, Any]] = [
        
    ]

    # Cho phép ghi đè đường dẫn mô hình qua CLI
    custom_model_path: Path = Path(sys.argv[1]) if len(sys.argv) > 1 else MODEL_PATH

    print("=" * 60)
    print("      DGA MODEL — INFERENCE TOOL (SELF-TEST)")
    print("=" * 60)
    print(f"  Model path : {custom_model_path}")
    print(f"  Queries    : {len(SAMPLE_QUERIES)} bản ghi")
    print("=" * 60)

    try:
        scored: list[dict[str, Any]] = score_dga(SAMPLE_QUERIES, model_path=custom_model_path)

        print(f"\n{'ID':>4}  {'Domain':<26} {'Label':<12} {'DGA Score':>10}")
        print("-" * 58)
        for rec in scored:
            score_bar: str = "▓" * int(rec["dga_score"] * 20)
            print(
                f"{rec['query_id']:>4}  {rec['domain']:<26} "
                f"{rec.get('label', 'N/A'):<12} "
                f"{rec['dga_score']:>8.4f}  {score_bar}"
            )
        print()

        # Kiểm tra tính bất biến của dữ liệu gốc
        assert "dga_score" not in SAMPLE_QUERIES[0], \
            "FAIL: Dữ liệu gốc bị sửa đổi — vi phạm immutability!"
        print("[PASS] Dữ liệu gốc không bị thay đổi (immutability OK).")
        print("[PASS] Self-test hoàn tất.\n")

    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}\n")
        sys.exit(1)