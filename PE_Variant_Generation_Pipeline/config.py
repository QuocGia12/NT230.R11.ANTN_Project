"""
Cấu hình cho pipeline sinh biến thể PE (Thành viên 2 - transformation framework).

Toàn bộ action được tái sử dụng trực tiếp từ TIER-MAL/proposed/actions/modifier.py,
KHÔNG viết lại logic biến đổi PE. File này chỉ định nghĩa:
  - Đường dẫn repo TIER-MAL (để import modifier.py).
  - Phân nhóm A / B / C theo đúng danh sách bạn đã chọn.
  - Cách chọn 2 action đại diện mỗi nhóm khi tạo tổ hợp (để kết quả tái lập được,
    không phụ thuộc random tại thời điểm chạy).
"""

import os
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────
# Đường dẫn
# ──────────────────────────────────────────────────────────────────────────

# Đường dẫn tới thư mục gốc của repo TIER-MAL đã clone (chứa proposed/actions/modifier.py)
TIER_MAL_REPO = Path(os.environ.get("TIER_MAL_REPO", "./TIER-MAL")).resolve()

# Đường dẫn dataset của bạn (theo cấu trúc dataset/original, dataset/variants, dataset/metadata)
DATASET_ROOT = Path(os.environ.get("DATASET_ROOT", "./dataset")).resolve()

ORIGINAL_MALWARE_DIR = DATASET_ROOT / "original" / "malware"
VARIANTS_DIR = DATASET_ROOT / "variants"
METADATA_DIR = DATASET_ROOT / "metadata"
TRANSFORMATION_CSV = METADATA_DIR / "transformation_results.csv"

# ──────────────────────────────────────────────────────────────────────────
# Phân nhóm action — đúng theo lựa chọn của bạn, không đổi tên/thêm bớt
# ──────────────────────────────────────────────────────────────────────────

GROUP_A = [
    "pad_overlay",
    "append_benign_data_overlay",
    "append_benign_binary_overlay",
    "add_strings_to_overlay",
]

GROUP_B = [
    "add_section_benign_data",
    "add_section_strings",
]

GROUP_C = [
    "modify_timestamp",
    "rename_section",
    "remove_debug",
    "break_optional_header_checksum",
    "modify_optional_header",
]

GROUPS = {"A": GROUP_A, "B": GROUP_B, "C": GROUP_C}

# ──────────────────────────────────────────────────────────────────────────
# Chọn action đại diện cho tổ hợp (2 action/nhóm, cố định — không random)
#
# Lý do cố định thay vì random.choice tại lúc chạy: nếu random mỗi lần chạy
# script sẽ chọn action khác nhau -> không tái lập được giữa các lần chạy.
# Đổi danh sách dưới đây nếu bạn muốn chọn 2 action khác làm đại diện.
# ──────────────────────────────────────────────────────────────────────────

PICK_A = GROUP_A[:2]   # ["pad_overlay", "append_benign_data_overlay"]
PICK_B = GROUP_B[:2]   # ["add_section_benign_data", "add_section_strings"] — B chỉ có 2 action nên PICK_B = cả nhóm B
PICK_C = GROUP_C[:2]   # ["modify_timestamp", "rename_section"]

# A_B_C: 2 x 2 x 2 = 8 tổ hợp đầy đủ, nhưng yêu cầu chỉ lấy 6.
# Lấy ngẫu nhiên có seed cố định (tái lập được) 6/8 tổ hợp.
# -> XÁC NHẬN LẠI VỚI NHÓM: nếu ý bạn là dùng đủ 8 tổ hợp, đặt ABC_COMBO_COUNT = 8.
ABC_COMBO_COUNT = 6
ABC_COMBO_SAMPLE_SEED = 20261101  # seed cố định chỉ dùng để CHỌN 6/8 tổ hợp nào

# ──────────────────────────────────────────────────────────────────────────
# Seed gốc cho toàn bộ pipeline (ảnh hưởng random bên trong từng action,
# ví dụ: add_section_benign_data chọn ngẫu nhiên file trusted nào, section
# name nào...). Mỗi (sample, transformation, bước) có seed dẫn xuất riêng
# từ seed gốc này -> kết quả tái lập được dù chạy song song hay đổi thứ tự.
# ──────────────────────────────────────────────────────────────────────────
BASE_SEED = int(os.environ.get("PIPELINE_BASE_SEED", "42"))

# Nếu True: tên file output có prefix tên family (thư mục malware/<family>/)
# để tránh trùng tên giữa các family khác nhau. Khuyến nghị giữ True.
PREFIX_FAMILY_IN_FILENAME = True

# Các đuôi file được coi là sample hợp lệ khi duyệt original/malware/**;
# để trống = nhận mọi file (không lọc theo đuôi).
ALLOWED_EXTENSIONS: set[str] = set()  # ví dụ {".exe", ".dll"} nếu muốn lọc
