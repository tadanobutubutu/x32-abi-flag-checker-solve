#!/usr/bin/env python3
# =============================================================================
# x32 ABI flag checker - Daily AlpacaHack
# カテゴリー: Rev | トピック: ABI | 難易度: Hard 8.0
# =============================================================================
# 【概要】
# 配布されるのは x32 ABI（ELFCLASS32 + Machine=x86-64）の静的リンク実行ファイルです。
# 多くの環境ではカーネルに CONFIG_X86_X32_ABI が無く実行できませんが、
# 静的解析だけで解けます。
#
# is_correct() は入力文字列の長さが 41（= 0x28 + 1）であることを要求し、
# 隣接する 2 文字のペアを 40 回にわたって次のように検査します。
#
#   v   = (flag[i] << 8) | flag[i+1]
#   val = (v * 0x3233504c49) XOR 0x4942412d323378   # "ILP32" / "x32-ABI"
#   h   = MD5(val をリトルエンディアン 8 バイトにしたもの)
#   h  == expected[i]   （.data 上の 16 バイト × 40 個）
#
# 隣接ペアは 1 文字ずつ重なるので、先頭から印字可能文字を総当たりすれば
# フラグ全体を復元できます。
#
# 【準備】
#   pip install pyelftools
#   （hashlib / struct は標準ライブラリ）
#
# 【使い方】
#   python3 solve.py /path/to/x32-abi-flag-checker
#
# ※ フラグはこのファイルには書かれていません。実行時に計算して表示します。
# =============================================================================

from __future__ import annotations

import hashlib  # MD5 計算
import struct   # 64 bit 整数 → リトルエンディアン 8 バイト
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile  # ELF から expected 配列を読む

# -----------------------------------------------------------------------------
# 定数（is_correct / some_proc のアセンブリから読み取った値）
# -----------------------------------------------------------------------------
# expected シンボルの仮想アドレス（.data セクション）
EXPECTED_VADDR = 0x4C40E0
# ペア数（フラグ長は PAIR_COUNT + 1 = 41）
PAIR_COUNT = 40
# MD5 ダイジェスト長
HASH_LEN = 16

# some_proc に渡される定数。リトルエンディアンで読むとそれぞれ
#   0x3233504c49      → b"ILP32"   （x32 のポインタモデル名）
#   0x4942412d323378  → b"x32-ABI" （ABI 名）
CONST_MUL = 0x3233504C49
CONST_XOR = 0x4942412D323378

# 印字可能 ASCII（スペース〜チルダ）
PRINTABLE = range(0x20, 0x7F)


def load_expected(path: Path) -> list[bytes]:
    """バイナリから expected[40][16] を読み出す。"""
    with path.open("rb") as f:
        elf = ELFFile(f)
        for segment in elf.iter_segments():
            vaddr = segment["p_vaddr"]
            memsz = segment["p_memsz"]
            if vaddr <= EXPECTED_VADDR < vaddr + memsz:
                # 仮想アドレス → ファイルオフセット
                file_offset = EXPECTED_VADDR - vaddr + segment["p_offset"]
                f.seek(file_offset)
                raw = f.read(PAIR_COUNT * HASH_LEN)
                break
        else:
            raise RuntimeError(
                f"仮想アドレス {EXPECTED_VADDR:#x} を含むセグメントが見つかりません"
            )

    if len(raw) != PAIR_COUNT * HASH_LEN:
        raise RuntimeError(f"expected の長さが不正です: {len(raw)} bytes")

    return [raw[i * HASH_LEN : (i + 1) * HASH_LEN] for i in range(PAIR_COUNT)]


def pair_hash(c1: int, c2: int) -> bytes:
    """2 文字 (c1, c2) に対する some_proc 相当の MD5 ダイジェストを返す。"""
    # (flag[i] << 8) | flag[i+1]
    v = (c1 << 8) | c2
    # 64 bit: (v * ILP32) XOR x32-ABI
    val = (v * CONST_MUL) & 0xFFFFFFFFFFFFFFFF
    val ^= CONST_XOR
    # リトルエンディアン 8 バイトを MD5
    return hashlib.md5(struct.pack("<Q", val)).digest()


def recover_flag(expected: list[bytes]) -> str:
    """
    重なり合う 2 文字ペアを先頭から総当たりしてフラグを復元する。

    i=0 では 2 文字とも未知なので c1,c2 を全探索し、
    i>=1 では c1 が直前ペアの c2（= flag[i]）に固定される。
    """
    flag = ""
    for i, target in enumerate(expected):
        found = False
        for c1 in PRINTABLE:
            # 2 文字目以降は前ペアの 2 文字目と一致必須
            if i > 0 and c1 != ord(flag[i]):
                continue
            for c2 in PRINTABLE:
                if pair_hash(c1, c2) != target:
                    continue
                if i == 0:
                    flag += chr(c1)
                flag += chr(c2)
                found = True
                break
            if found:
                break
        if not found:
            raise RuntimeError(f"ペア {i} で一致する文字が見つかりませんでした")
    return flag


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/x32-abi-flag-checker", file=sys.stderr)
        raise SystemExit(2)

    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"ファイルが見つかりません: {path}", file=sys.stderr)
        raise SystemExit(1)

    print(f"[*] loading expected hashes from {path}")
    expected = load_expected(path)
    print(f"[*] {len(expected)} blocks × {HASH_LEN} bytes")
    print(f"[*] CONST_MUL = {CONST_MUL:#x}  (ILP32)")
    print(f"[*] CONST_XOR = {CONST_XOR:#x}  (x32-ABI)")

    print("[*] brute-forcing overlapping character pairs ...")
    flag = recover_flag(expected)
    print(f"[+] recovered ({len(flag)} chars): {flag}")


if __name__ == "__main__":
    main()
