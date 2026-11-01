"""
Kiểm tra PE validity sau biến đổi.

`proposed/actions/integrity.py` của repo chỉ kiểm tra lief.PE.parse() không
trả None — khá yếu. Ở đây kiểm tra thêm bằng pefile và vài điều kiện cấu trúc
cơ bản, đúng tinh thần đề bài ("Xây dựng pipeline kiểm tra PE có còn hoạt
động đúng hay không" — đây là lớp kiểm tra tĩnh, không thay cho functionality
test trên VM của Thành viên 1, chỉ lọc bỏ sớm những PE rõ ràng đã hỏng cấu trúc).
"""

from dataclasses import dataclass

import lief
import pefile


@dataclass
class ValidityResult:
    valid_lief: bool
    valid_pefile: bool
    valid: bool          # AND của cả hai + các điều kiện cấu trúc bên dưới
    error: str = ""


def check_pe_validity(bytez: bytes) -> ValidityResult:
    # 1) lief phải parse được
    valid_lief = False
    try:
        valid_lief = lief.PE.parse(list(bytez)) is not None
    except Exception as e:
        return ValidityResult(False, False, False, f"lief parse error: {e}")

    if not valid_lief:
        return ValidityResult(False, False, False, "lief.PE.parse trả về None")

    # 2) pefile phải parse được + vài điều kiện cấu trúc cơ bản
    try:
        pe = pefile.PE(data=bytez, fast_load=False)
    except Exception as e:
        return ValidityResult(valid_lief, False, False, f"pefile parse error: {e}")

    try:
        errors = []

        # Số section khai báo trong header phải khớp số section thực tế đọc được
        declared = pe.FILE_HEADER.NumberOfSections
        actual = len(pe.sections)
        if declared != actual:
            errors.append(f"NumberOfSections={declared} nhưng đọc được {actual} section")

        # Entry point phải nằm trong phạm vi một section nào đó (nếu có entry point)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep != 0:
            in_some_section = any(
                s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                for s in pe.sections
            )
            if not in_some_section:
                errors.append(f"AddressOfEntryPoint=0x{ep:x} không nằm trong section nào")

        # SizeOfImage phải >= điểm kết thúc xa nhất của các section (căn theo SectionAlignment)
        if pe.sections:
            furthest = max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections)
            if pe.OPTIONAL_HEADER.SizeOfImage < furthest:
                errors.append(
                    f"SizeOfImage=0x{pe.OPTIONAL_HEADER.SizeOfImage:x} nhỏ hơn "
                    f"vùng section xa nhất 0x{furthest:x}"
                )

        valid_pefile = len(errors) == 0
        error_msg = "; ".join(errors)
    finally:
        pe.close()

    valid = valid_lief and valid_pefile
    return ValidityResult(valid_lief, valid_pefile, valid, error_msg)
