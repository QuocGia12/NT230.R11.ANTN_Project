# PE Variant Generation Pipeline — Thành viên 2

Sinh biến thể PE bằng các action **có sẵn** trong `TIER-MAL/proposed/actions/modifier.py`
(không viết lại logic biến đổi), theo nhóm A/B/C bạn đã chọn, và ghi kết quả vào
`transformation_results.csv`.

Đã test thực tế trên máy (clone repo thật, chạy pipeline trên 2 file PE hợp lệ lấy
từ `proposed/actions/trusted/`): **58/58 biến thể sinh thành công, 58/58 valid PE**,
và chạy lại lần 2 cho **sha256 giống hệt lần 1** (seed dẫn xuất đúng, tái lập được).

## Cài đặt

```bash
git clone https://github.com/nanad017/TIER-MAL.git
pip install "lief==0.14.1" "pefile>=2023.2.7"   # BẮT BUỘC pin lief, xem phần "Vấn đề lief version"
pip install gym scikit-learn                     # chỉ để thoả import phụ, xem actions_bridge.py
```

## Chạy

```bash
export TIER_MAL_REPO=/path/to/TIER-MAL
export DATASET_ROOT=/path/to/dataset   # chứa dataset/original/malware/<family>/<sample>

python3 generate_variants.py --dry-run     # xem kế hoạch, không ghi file
python3 generate_variants.py               # chạy thật
python3 generate_variants.py --limit-samples 3   # debug nhanh trên 3 sample
```

Yêu cầu cấu trúc đầu vào:

```
dataset/
└── original/
    └── malware/
        ├── Locker/*.exe
        ├── Mediyes/*.exe
        ├── Winwebsec/*.exe
        ├── Zbot/*.exe
        └── Zeroaccess/*.exe
```

Output sinh ra:

```
dataset/
├── variants/{A,B,C,A_B,A_C,B_C,A_B_C}/...
└── metadata/transformation_results.csv
```

## Số lượng biến thể mỗi sample gốc

| Nhóm | Số lượng | Cách chọn |
|---|---|---|
| A | 4 | mỗi action trong A, riêng lẻ |
| B | 2 | mỗi action trong B, riêng lẻ |
| C | 5 | mỗi action trong C, riêng lẻ |
| A_B | 4 | 2 action đại diện của A × 2 action đại diện của B |
| A_C | 4 | 2 action đại diện của A × 2 action đại diện của C |
| B_C | 4 | 2 action đại diện của B × 2 action đại diện của C |
| A_B_C | 6 | lấy 6/8 tổ hợp (2×2×2) — xem phần "CẦN BẠN XÁC NHẬN" |
| **Tổng** | **29** | mỗi sample gốc → 29 file biến thể |

2 action đại diện mỗi nhóm được chọn **cố định** trong `config.py`
(`PICK_A`, `PICK_B`, `PICK_C` — mặc định lấy 2 action đầu danh sách), không
`random.choice` tại lúc chạy, để kết quả không đổi giữa các lần chạy. Vì B chỉ
có đúng 2 action, `PICK_B` thực chất là toàn bộ nhóm B.

## ⚠️ CẦN BẠN XÁC NHẬN: A_B_C là 6 hay 8 tổ hợp?

Đề bạn ghi "6 thay đổi (A+B+C, 2 thay đổi A, 2 thay đổi B, 2 thay đổi C)" — nhưng
2×2×2 = 8, không phải 6. Pipeline hiện lấy ngẫu nhiên có seed cố định
(`ABC_COMBO_SAMPLE_SEED` trong `config.py`) 6 trong 8 tổ hợp, để đúng số lượng bạn
yêu cầu và vẫn tái lập được. Nếu ý bạn thực ra là dùng đủ cả 8, chỉ cần đổi:

```python
# config.py
ABC_COMBO_COUNT = 8
```

## Vấn đề phiên bản `lief` (đã gặp và đã xử lý)

`modifier.py` được viết cho `lief>=0.12.2` (Python 3.7.17, theo
`configs/requirements.txt` + `scripts/setup_rl_env.sh` của repo). Nếu bạn cài
`lief` bằng `pip install lief` bình thường trên Python mới, sẽ dính 2 lỗi API:

1. **`lief` ≥ 1.0.0**: `lief.PE.SECTION_TYPES` bị xoá hẳn
   → `add_section_benign_data`, `add_section_strings` lỗi `AttributeError`.
   **Không có shim nào vá được** vì enum bị xoá hoàn toàn, không còn chỗ trỏ lại.
   → Bắt buộc dùng `lief==0.14.1` hoặc cũ hơn.

2. **`lief` 0.14.x**: `lief.PE.DATA_DIRECTORY` đổi tên thành `lief.PE.DataDirectory.TYPES`
   → `remove_debug` lỗi `AttributeError`.
   → `actions_bridge.py` đã tự vá lỗi này bằng một dòng alias, **đã test chạy đúng**.

**Khuyến nghị tốt nhất**: dùng đúng venv repo tự dựng
(`PYTHON_BIN=python3.7 bash scripts/setup_rl_env.sh`) để có `lief` đúng bản
`modifier.py` được viết ra từ đầu, thay vì dựa vào shim.

## Cách tái lập (reproducibility)

Mỗi bước biến đổi của mỗi sample có seed riêng, dẫn xuất từ
`sha256(BASE_SEED | đường_dẫn_sample | vị_trí_bước | tên_action)` — xem
`generate_variants.derive_seed()`. Vì vậy:

- Chạy lại toàn bộ pipeline nhiều lần → **sha256_after giống hệt nhau** (đã kiểm chứng).
- Không phụ thuộc thứ tự xử lý sample hay chạy song song.
- Đổi `BASE_SEED` trong `config.py` (hoặc biến môi trường `PIPELINE_BASE_SEED`)
  → toàn bộ dataset biến thể đổi theo, nhưng vẫn tái lập được với seed đó.

## Cột trong `transformation_results.csv`

| Cột | Ý nghĩa |
|---|---|
| `record_id` | id duy nhất của dòng |
| `family` | tên thư mục family (Locker, Zbot, ...) |
| `parent_sample` | đường dẫn tương đối của PE gốc trong `original/malware/` |
| `group` | A / B / C / A_B / A_C / B_C / A_B_C |
| `transformations` | action áp dụng, nối bằng `+`, đúng thứ tự |
| `transformation_order` | list tường minh thứ tự các bước |
| `seed_used` | `BASE_SEED` dùng để dẫn xuất seed từng bước |
| `success` | pipeline chạy xong không lỗi |
| `changed` | bytes có thực sự đổi so với gốc không |
| `valid_pe_lief` / `valid_pe_pefile` / `valid_pe` | kết quả kiểm tra cấu trúc PE (xem `validity.py`) |
| `output_path` | đường dẫn tương đối trong `dataset/variants/` |
| `sha256_before` / `sha256_after` | hash PE gốc và PE sau biến đổi |
| `size_before` / `size_after` | kích thước (byte) |
| `error_message` | lỗi nếu có (exception hoặc lỗi validity) |
| `step_details` | JSON chi tiết `changed`/`error` từng bước trong chain |

`valid_pe` ở đây là **kiểm tra tĩnh cấu trúc PE** (lief parse được + pefile parse
được + entry point nằm trong section + SizeOfImage hợp lý). Đây **không thay thế**
functionality test trên VM của Thành viên 1 — theo đúng lưu ý trong đề bài:
*"Kết quả functionality không xác định phải ghi INCONCLUSIVE, không tự động tính
là PASS"*. File `functionality_results.csv` của Duyên join vào bằng cột
`output_path` (= `sample_id` phía Member 1) để ra bảng thống kê cuối cùng.

## Những điểm mình tự quyết định khi code — bạn nên rà lại

1. **Tên file có prefix family** (`<family>_<name>_<action>.exe`) để tránh trùng
   tên giữa các family khác nhau trong cùng một thư mục `variants/A/` (thư mục đó
   không chia theo family). Tắt bằng `config.PREFIX_FAMILY_IN_FILENAME = False`
   nếu tên sample của bạn đã đảm bảo duy nhất.
2. **Thứ tự áp dụng trong combo = thứ tự chữ cái** (A trước, B, rồi C) — đã test
   thực nghiệm việc A trước hay sau B không ảnh hưởng tới overlay, nên chọn theo
   thứ tự tên cho dễ đọc log, không phải vì bắt buộc kỹ thuật.
3. ~~`add_strings_to_overlay` nằm trong nhóm B~~ — đã chuyển sang nhóm A theo yêu
   cầu cập nhật của bạn (đúng vị trí hơn, vì action này append vào overlay).
   `add_bytes_to_section_cave` và `add_imports` đã bị bỏ khỏi B.
