#!/usr/bin/env python3
"""
Sinh biến thể PE từ dataset/original/malware/<family>/<sample> bằng các action
có sẵn trong TIER-MAL (proposed/actions/modifier.py), theo đúng yêu cầu:

  - Riêng lẻ từng action trong A -> dataset/variants/A/
  - Riêng lẻ từng action trong B -> dataset/variants/B/
  - Riêng lẻ từng action trong C -> dataset/variants/C/
  - Tổ hợp 2 nhóm (A_B, A_C, B_C): 2 action đại diện x 2 action đại diện = 4 biến thể/cặp nhóm
  - Tổ hợp 3 nhóm (A_B_C): 2x2x2=8 tổ hợp đầy đủ, lấy 6 (xem config.ABC_COMBO_COUNT)
  - Ghi toàn bộ kết quả vào dataset/metadata/transformation_results.csv

Cách chạy:
    TIER_MAL_REPO=/path/to/TIER-MAL DATASET_ROOT=/path/to/dataset \
        python3 generate_variants.py

    # chạy thử trước (không ghi file, chỉ in ra kế hoạch):
    python3 generate_variants.py --dry-run

Yêu cầu: pip install "lief==0.14.1" "pefile>=2023.2.7"
(KHÔNG dùng lief bản 1.0.0 trở lên — API add_section đã đổi, xem README).
"""

import os 
import argparse
import csv
import hashlib
import itertools
import random
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import config
from actions_bridge import ModifyBinary
from validity import check_pe_validity

CSV_FIELDS = [
    "record_id",
    "timestamp",
    "family",
    "parent_sample",          # đường dẫn tương đối của PE gốc trong original/malware
    "group",                  # A / B / C / A_B / A_C / B_C / A_B_C
    "transformations",        # action áp dụng, nối bằng "+", đúng thứ tự
    "transformation_order",   # JSON list, tường minh thứ tự các bước
    "seed_used",              # seed gốc (BASE_SEED) dùng để dẫn xuất seed từng bước
    "success",                # pipeline chạy xong không lỗi (True/False)
    "changed",                # bytes có thực sự thay đổi so với input không
    "valid_pe_original",      # PE GỐC (trước biến đổi) có hợp lệ không — tách
                               # "hỏng sẵn từ đầu" khỏi "bị transformation làm hỏng"
    "valid_pe_lief",
    "valid_pe_pefile",
    "valid_pe",                # AND của 2 cột trên
    "output_path",             # đường dẫn tương đối trong dataset/variants/
    "sha256_before",
    "sha256_after",
    "size_before",
    "size_after",
    "error_message",
    "step_details",            # JSON: chi tiết changed/error từng bước trong chain
]


# ──────────────────────────────────────────────────────────────────────────
# Seed dẫn xuất: mỗi bước (sample, vị trí trong chain, action) có seed riêng,
# tính từ BASE_SEED -> kết quả tái lập được dù chạy song song / đổi thứ tự xử lý.
# ──────────────────────────────────────────────────────────────────────────
def derive_seed(base_seed: int, sample_relpath: str, step_index: int, action: str) -> int:
    key = f"{base_seed}|{sample_relpath}|{step_index}|{action}".encode("utf-8")
    return int(hashlib.sha256(key).hexdigest()[:8], 16)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class StepResult:
    action: str
    changed: bool
    error: str = ""


@dataclass
class ChainResult:
    bytez: bytes
    success: bool
    changed: bool
    steps: list = field(default_factory=list)
    error_message: str = ""


def apply_action_chain(original_bytez: bytes, actions: list, base_seed: int, sample_relpath: str) -> ChainResult:
    """Áp dụng tuần tự một danh sách action lên bytez, mỗi bước seed riêng (xem derive_seed)."""
    bytez = original_bytez
    steps = []
    overall_changed = False
    try:
        for i, action in enumerate(actions):
            step_seed = derive_seed(base_seed, sample_relpath, i, action)
            random.seed(step_seed)
            before = bytez
            mb = ModifyBinary(bytez)
            bytez = getattr(mb, action)()
            changed = bytez != before
            overall_changed = overall_changed or changed
            steps.append(StepResult(action=action, changed=changed))
        return ChainResult(bytez=bytez, success=True, changed=overall_changed, steps=steps)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        steps.append(StepResult(action=action, changed=False, error=err))
        return ChainResult(
            bytez=original_bytez, success=False, changed=False, steps=steps, error_message=err
        )


# ──────────────────────────────────────────────────────────────────────────
# Danh sách sample gốc
# ──────────────────────────────────────────────────────────────────────────
def iter_malware_samples():
    """Trả về (family, relpath_to_original_malware, Path tuyệt đối)."""
    root = config.ORIGINAL_MALWARE_DIR
    if not root.exists():
        raise FileNotFoundError(f"Không tìm thấy {root}")
    for family_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for f in sorted(family_dir.rglob("*")):
            if not f.is_file():
                continue
            if config.ALLOWED_EXTENSIONS and f.suffix.lower() not in config.ALLOWED_EXTENSIONS:
                continue
            relpath = f.relative_to(root)
            yield family_dir.name, str(relpath), f


def output_stem(family: str, sample_path: Path) -> str:
    stem = sample_path.stem
    if config.PREFIX_FAMILY_IN_FILENAME:
        return f"{family}_{stem}"
    return stem


def output_ext(sample_path: Path) -> str:
    return sample_path.suffix if sample_path.suffix else ".exe"


# ──────────────────────────────────────────────────────────────────────────
# Danh sách công việc cần sinh (nhóm, tên thư mục output, danh sách action chain)
# ──────────────────────────────────────────────────────────────────────────
def build_abc_combos():
    all_combos = list(itertools.product(config.PICK_A, config.PICK_B, config.PICK_C))
    if config.ABC_COMBO_COUNT >= len(all_combos):
        return all_combos
    rng = random.Random(config.ABC_COMBO_SAMPLE_SEED)
    return rng.sample(all_combos, config.ABC_COMBO_COUNT)


def build_jobs_for_sample():
    """Trả về list of (group_label, actions_tuple) áp dụng cho MỌI sample."""
    jobs = []

    # Riêng lẻ
    for a in config.GROUP_A:
        jobs.append(("A", (a,)))
    for b in config.GROUP_B:
        jobs.append(("B", (b,)))
    for c in config.GROUP_C:
        jobs.append(("C", (c,)))

    # Tổ hợp 2 nhóm: 2 x 2 = 4 mỗi cặp
    for a, b in itertools.product(config.PICK_A, config.PICK_B):
        jobs.append(("A_B", (a, b)))
    for a, c in itertools.product(config.PICK_A, config.PICK_C):
        jobs.append(("A_C", (a, c)))
    for b, c in itertools.product(config.PICK_B, config.PICK_C):
        jobs.append(("B_C", (b, c)))

    # Tổ hợp 3 nhóm: config.ABC_COMBO_COUNT trong 8 tổ hợp đầy đủ
    for a, b, c in build_abc_combos():
        jobs.append(("A_B_C", (a, b, c)))

    return jobs


def output_filename(group_label: str, stem: str, ext: str, actions: tuple) -> str:
    if len(actions) == 1:
        return f"{stem}_{actions[0]}{ext}"
    if len(actions) == 2:
        return f"{stem}_{actions[0]}_{actions[1]}{ext}"
    if len(actions) == 3:
        # Theo đúng format bạn yêu cầu: <name>_<t1>_<t2>-<t3>
        return f"{stem}_{actions[0]}_{actions[1]}-{actions[2]}{ext}"
    raise ValueError(f"Không hỗ trợ chain {len(actions)} action")


# ──────────────────────────────────────────────────────────────────────────
# Checkpoint: resume theo từng SAMPLE GỐC.
#
# Nguyên tắc: một sample chỉ được coi là "đã xong" nếu nó có ĐỦ và ĐÚNG tập
# (group, transformations) như jobs_template hiện tại. Nếu thiếu dòng (do lần
# chạy trước bị ngắt giữa chừng ở sample đó) hoặc tập transformation không
# khớp (do bạn đổi config.py giữa 2 lần chạy), sample đó bị coi là CHƯA xong
# và sẽ được xử lý lại TOÀN BỘ từ đầu (ghi đè các file/dòng cũ của nó) — nhờ
# vậy không bao giờ có dòng CSV nửa vời hay bị trùng record_id.
#
# CSV được ghi đè lại TOÀN BỘ (không phải append) ngay sau khi mỗi sample xử
# lý xong, nên nếu quá trình bị ngắt, bạn mất tối đa đúng 1 sample đang dở,
# không mất các sample đã hoàn thành trước đó.
# ──────────────────────────────────────────────────────────────────────────
def expected_keys_for_jobs(jobs_template) -> set:
    return {(group_label, "+".join(actions)) for group_label, actions in jobs_template}


def load_checkpoint(jobs_template):
    """
    Trả về (rows_so_far, done_sample_relpaths, next_record_id).
    rows_so_far: list các dict dòng CSV của những sample đã xử lý ĐỦ và ĐÚNG.
    """
    if not config.TRANSFORMATION_CSV.exists():
        return [], set(), 1

    with open(config.TRANSFORMATION_CSV, "r", newline="", encoding="utf-8") as f:
        existing_rows = list(csv.DictReader(f))

    if not existing_rows:
        return [], set(), 1

    expected = expected_keys_for_jobs(jobs_template)

    by_sample = {}
    for row in existing_rows:
        by_sample.setdefault(row["parent_sample"], []).append(row)

    kept_rows = []
    done_samples = set()
    for parent_sample, sample_rows in by_sample.items():
        sample_keys = {(r["group"], r["transformations"]) for r in sample_rows}
        if sample_keys == expected and len(sample_rows) == len(jobs_template):
            kept_rows.extend(sample_rows)
            done_samples.add(parent_sample)
        else:
            print(f"[checkpoint] Sample '{parent_sample}' trong CSV cũ KHÔNG đủ/khớp "
                  f"transformation hiện tại ({len(sample_rows)}/{len(jobs_template)}) "
                  f"-> sẽ xử lý lại từ đầu.")

    next_record_id = 1
    if kept_rows:
        next_record_id = max(int(r["record_id"]) for r in kept_rows) + 1

    return kept_rows, done_samples, next_record_id


def write_csv(rows):
    """Ghi CSV an toàn bằng atomic replace."""
    config.METADATA_DIR.mkdir(parents=True, exist_ok=True)

    temp_csv = config.TRANSFORMATION_CSV.with_name(
        config.TRANSFORMATION_CSV.name + ".tmp"
    )

    try:
        with open(temp_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
            f.flush()
            os.fsync(f.fileno())

        # Chỉ thay thế CSV cũ sau khi ghi file tạm thành công
        os.replace(temp_csv, config.TRANSFORMATION_CSV)

    finally:
        if temp_csv.exists():
            temp_csv.unlink()


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Chỉ in kế hoạch, không ghi file/CSV")
    parser.add_argument("--limit-samples", type=int, default=None, help="Giới hạn số sample gốc xử lý (debug)")
    parser.add_argument("--fresh", action="store_true",
                         help="Bỏ qua checkpoint cũ, xử lý lại TOÀN BỘ từ đầu "
                              "(ghi đè transformation_results.csv hiện có)")
    args = parser.parse_args()

    jobs_template = build_jobs_for_sample()
    print(f"[info] Tổng số transformation/sample: {len(jobs_template)}")
    print(f"[info]   - Riêng lẻ: A={len(config.GROUP_A)}, B={len(config.GROUP_B)}, C={len(config.GROUP_C)}")
    print(f"[info]   - Tổ hợp 2 nhóm: A_B=4, A_C=4, B_C=4")
    print(f"[info]   - Tổ hợp 3 nhóm A_B_C: {config.ABC_COMBO_COUNT}/8 "
          f"(seed chọn tổ hợp = {config.ABC_COMBO_SAMPLE_SEED})")

    if args.dry_run:
        for group_label, actions in jobs_template:
            print(f"  [{group_label}] {'+'.join(actions)}")
        print("[dry-run] Không ghi file. Thoát.")
        return

    for d in ("A", "B", "C", "A_B", "A_C", "B_C", "A_B_C"):
        (config.VARIANTS_DIR / d).mkdir(parents=True, exist_ok=True)
    config.METADATA_DIR.mkdir(parents=True, exist_ok=True)

    if args.fresh and config.TRANSFORMATION_CSV.exists():
        config.TRANSFORMATION_CSV.unlink()
        print("[checkpoint] --fresh: đã xoá checkpoint cũ, xử lý lại từ đầu.")

    rows, done_samples, record_id_counter = load_checkpoint(jobs_template)
    if done_samples:
        print(f"[checkpoint] Tìm thấy {len(done_samples)} sample đã xử lý ĐỦ ở lần chạy trước "
              f"-> bỏ qua, chỉ xử lý sample còn lại.")

    n_samples = 0           # đếm MỌI sample duyệt qua (kể cả bỏ qua vì đã xong)
    n_samples_processed = 0 # đếm sample thực sự được xử lý ở lần chạy này
    n_samples_invalid_original = 0

    try:
        for family, relpath, abs_path in iter_malware_samples():
            if args.limit_samples is not None and n_samples >= args.limit_samples:
                break

            n_samples += 1

            if relpath in done_samples:
                print(f"[{n_samples}] {relpath} -> [checkpoint] đã xong, bỏ qua")
                continue

            n_samples_processed += 1
            original_bytez = abs_path.read_bytes()
            sha_before = sha256_hex(original_bytez)
            size_before = len(original_bytez)
            stem = output_stem(family, abs_path)
            ext = output_ext(abs_path)

            original_validity = check_pe_validity(original_bytez)

            if not original_validity.valid:
                n_samples_invalid_original += 1
                print(
                    f"    [cảnh báo] PE gốc {relpath} đã KHÔNG hợp lệ "
                    f"trước khi biến đổi: {original_validity.error}"
                )

            print(f"[{n_samples}] {relpath} ({size_before} bytes)")

            for group_label, actions in jobs_template:
                record_id = record_id_counter
                record_id_counter += 1

                result = apply_action_chain(
                    original_bytez,
                    list(actions),
                    config.BASE_SEED,
                    relpath
                )

                out_name = output_filename(group_label, stem, ext, actions)
                out_rel = Path(group_label) / out_name
                out_abs = config.VARIANTS_DIR / out_rel

                valid = check_pe_validity(result.bytez) if result.success else None

                if result.success:
                    out_abs.write_bytes(result.bytez)

                step_details = [
                    {
                        "action": s.action,
                        "changed": s.changed,
                        "error": s.error
                    }
                    for s in result.steps
                ]

                rows.append({
                    "record_id": record_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "family": family,
                    "parent_sample": relpath,
                    "group": group_label,
                    "transformations": "+".join(actions),
                    "transformation_order": str(list(actions)),
                    "seed_used": config.BASE_SEED,
                    "success": result.success,
                    "changed": result.changed,
                    "valid_pe_original": original_validity.valid,
                    "valid_pe_lief": valid.valid_lief if valid else False,
                    "valid_pe_pefile": valid.valid_pefile if valid else False,
                    "valid_pe": valid.valid if valid else False,
                    "output_path": str(out_rel) if result.success else "",
                    "sha256_before": sha_before,
                    "sha256_after": sha256_hex(result.bytez) if result.success else "",
                    "size_before": size_before,
                    "size_after": len(result.bytez) if result.success else 0,
                    "error_message": result.error_message or (valid.error if valid else ""),
                    "step_details": str(step_details),
                })

            # CHECKPOINT: chỉ lưu sau khi hoàn thành toàn bộ transformations
            # của sample hiện tại.
            write_csv(rows)
            done_samples.add(relpath)

            print(
                f"[checkpoint] Saved: {relpath} "
                f"({len(rows)} records total)"
            )

    except KeyboardInterrupt:
        print("\n\n[interrupt] Nhận Ctrl+C!")

        # Lưu cả những record đã hoàn thành trong sample đang xử lý.
        # Sample chưa đủ transformations sẽ tự động bị loại khi load_checkpoint.
        write_csv(rows)

        print(f"[checkpoint] Đã lưu metadata: {config.TRANSFORMATION_CSV}")
        print("[checkpoint] Những sample hoàn thành sẽ được giữ nguyên.")
        print("[checkpoint] Sample đang xử lý dở sẽ được chạy lại khi resume.")
        print("[interrupt] Thoát an toàn.")

        return

    with open(config.TRANSFORMATION_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    n_ok = sum(1 for r in rows if r["success"])
    n_valid = sum(1 for r in rows if r["valid_pe"])
    print(f"\n[done] {n_samples} sample gốc x {len(jobs_template)} transformation = {len(rows)} dòng")
    print(f"[done] success={n_ok}/{len(rows)}  valid_pe={n_valid}/{len(rows)}")
    print(f"[done] sample gốc đã KHÔNG hợp lệ từ trước khi biến đổi: "
          f"{n_samples_invalid_original}/{n_samples}")
    print(f"[done] CSV: {config.TRANSFORMATION_CSV}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
