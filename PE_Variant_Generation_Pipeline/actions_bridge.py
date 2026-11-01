"""
Import ModifyBinary trực tiếp từ TIER-MAL/proposed/actions/modifier.py mà
KHÔNG import package `proposed` theo cách thông thường.

Lý do cần làm vậy: `proposed/__init__.py` có side-effect nặng khi import
(đăng ký Gym env, đọc sha256 từ runtime/samples, yêu cầu dataset RL đã có sẵn
theo đúng cấu trúc của repo). Pipeline của mình chỉ cần class ModifyBinary và
ACTION_TABLE trong modifier.py, không cần toàn bộ RL stack, nên ta nạp thẳng
module modifier.py bằng importlib, tự tạo package giả `proposed` / `proposed.actions`
trong sys.modules để các import tương đối (`from .api_groups import ...`)
trong modifier.py vẫn hoạt động bình thường.

Đã test thực nghiệm (xem README) với lief==0.14.1. Lưu ý: lief bản mới nhất
(1.0.0 tại thời điểm viết) đổi API `lief.PE.SECTION_TYPES` khiến
`add_section_benign_data` / `add_section_strings` lỗi. BẮT BUỘC pin lief.
"""

import sys
import types
import importlib.util
from pathlib import Path

import lief

import config


def _apply_lief_compat_shims():
    """
    modifier.py được viết cho lief>=0.12.2 (xem configs/requirements.txt của repo,
    dùng trong venv Python 3.7.17 do scripts/setup_rl_env.sh dựng). Nếu bạn chạy
    pipeline này trong môi trường khác (vd: Python 3.10+ với lief mới hơn cài qua
    pip thông thường), một số tên enum đã đổi giữa các phiên bản lief:

      - lief 0.14.x : có `SECTION_TYPES`, KHÔNG có `DATA_DIRECTORY` (đổi thành
        `lief.PE.DataDirectory.TYPES`) -> remove_debug() lỗi AttributeError.
      - lief 1.0.0+ : KHÔNG có cả `SECTION_TYPES` lẫn `DATA_DIRECTORY`
        -> add_section_benign_data()/add_section_strings() cũng lỗi.

    Khuyến nghị THỰC SỰ: dùng đúng venv của repo
        PYTHON_BIN=python3.7 bash scripts/setup_rl_env.sh
    để có lief đúng phiên bản modifier.py được viết ra, thay vì dựa vào shim này.
    Shim dưới đây chỉ vá lỗi đặt-tên-lại cho DATA_DIRECTORY (đã test với lief
    0.14.1) để pipeline chạy được trong môi trường hiện có; nó KHÔNG vá được
    lief >= 1.0.0 vì SECTION_TYPES đã bị xoá hẳn, không còn chỗ để trỏ lại.
    """
    if not hasattr(lief.PE, "DATA_DIRECTORY") and hasattr(lief.PE, "DataDirectory"):
        lief.PE.DATA_DIRECTORY = lief.PE.DataDirectory.TYPES

    if not hasattr(lief.PE, "SECTION_TYPES"):
        raise RuntimeError(
            f"lief=={lief.__version__} không còn `lief.PE.SECTION_TYPES` "
            "(bị xoá từ lief 1.0.0). add_section_benign_data/add_section_strings "
            "sẽ lỗi. Hãy cài đúng bản được repo pin, ví dụ: "
            'pip install "lief==0.14.1" --break-system-packages, '
            "hoặc tốt nhất là dùng venv do scripts/setup_rl_env.sh dựng."
        )


_apply_lief_compat_shims()


def _load_modifier_module():
    repo = config.TIER_MAL_REPO
    actions_dir = repo / "proposed" / "actions"
    modifier_path = actions_dir / "modifier.py"

    if not modifier_path.exists():
        raise FileNotFoundError(
            f"Không tìm thấy {modifier_path}. Kiểm tra lại biến môi trường "
            f"TIER_MAL_REPO (hiện tại: {repo}) có trỏ đúng tới repo TIER-MAL đã clone."
        )

    if "proposed.actions.modifier" in sys.modules:
        return sys.modules["proposed.actions.modifier"]

    # Package giả `proposed` — không chạy proposed/__init__.py thật.
    proposed_pkg = types.ModuleType("proposed")
    proposed_pkg.__path__ = [str(repo / "proposed")]
    sys.modules.setdefault("proposed", proposed_pkg)

    # Package giả `proposed.actions` — không chạy proposed/actions/__init__.py
    # (file này thực ra rỗng nên không sao, nhưng vẫn làm giả cho nhất quán).
    actions_pkg = types.ModuleType("proposed.actions")
    actions_pkg.__path__ = [str(actions_dir)]
    sys.modules.setdefault("proposed.actions", actions_pkg)

    spec = importlib.util.spec_from_file_location(
        "proposed.actions.modifier", str(modifier_path)
    )
    modifier = importlib.util.module_from_spec(spec)
    sys.modules["proposed.actions.modifier"] = modifier
    spec.loader.exec_module(modifier)
    return modifier


_modifier = _load_modifier_module()

ModifyBinary = _modifier.ModifyBinary
modify_sample_with_report = _modifier.modify_sample_with_report
ACTION_TABLE = _modifier.ACTION_TABLE

# Kiểm tra sanity: mọi action trong config.py phải tồn tại thật trong repo.
_missing = []
for group_name, actions in config.GROUPS.items():
    for action in actions:
        if action not in ACTION_TABLE:
            _missing.append(f"{group_name}:{action}")
if _missing:
    raise RuntimeError(
        "Các action sau không tồn tại trong ACTION_TABLE của modifier.py "
        f"(kiểm tra lại tên trong config.py): {_missing}"
    )
