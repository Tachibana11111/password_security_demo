import hashlib
import time
import sys
import os
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

VICTIM_PASSWORD = "123456"
MAX_ATTEMPTS_BCRYPT  = 500
MAX_ATTEMPTS_ARGON2  = 200

USE_WORDLIST  = "--wordlist" in sys.argv
WORDLIST_PATH = None
TEST_ALL      = "--all" in sys.argv

if USE_WORDLIST:
    idx = sys.argv.index("--wordlist")
    if idx + 1 < len(sys.argv):
        WORDLIST_PATH = sys.argv[idx + 1]

def section(title: str) -> None:
    print(f"\n{'='*57}")
    print(f"  {title}")
    print('='*57)

def build_wordlist() -> list[str]:
    common = [
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "abc123", "monkey", "1234567", "dragon",
        "master", "sunshine", "princess", "welcome", "shadow",
        "superman", "michael", "football", "iloveyou", "batman",
        "trustno1", "baseball", "123456789", "654321", "hello",
        "charlie", "donald", "password1", "qwerty123", "pass123",
    ]
    if VICTIM_PASSWORD not in common:
        common.insert(5, VICTIM_PASSWORD)
    return common

def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"  Đã load {len(words):,} password từ {os.path.basename(path)}")
        return words
    except FileNotFoundError:
        print(f"  Không tìm thấy file: {path}")
        print("     → Dùng wordlist mặc định thay thế.")
        return build_wordlist()

def crack_md5(target_hash: str, wordlist: list[str]) -> dict:
    start     = time.perf_counter()
    attempts  = 0
    found_pw  = None

    for word in wordlist:
        attempts += 1
        if hashlib.md5(word.encode()).hexdigest() == target_hash:
            found_pw = word
            break

    elapsed = time.perf_counter() - start
    return {
        "found":    found_pw,
        "attempts": attempts,
        "elapsed":  elapsed,
        "speed":    attempts / elapsed if elapsed > 0 else 0,
    }

def crack_sha1(target_hash: str, wordlist: list[str]) -> dict:
    start    = time.perf_counter()
    attempts = 0
    found_pw = None

    for word in wordlist:
        attempts += 1
        if hashlib.sha1(word.encode()).hexdigest() == target_hash:
            found_pw = word
            break

    elapsed = time.perf_counter() - start
    return {
        "found":    found_pw,
        "attempts": attempts,
        "elapsed":  elapsed,
        "speed":    attempts / elapsed if elapsed > 0 else 0,
    }

def crack_bcrypt_limited(target_hash: bytes, wordlist: list[str],
                          max_attempts: int = MAX_ATTEMPTS_BCRYPT) -> dict:
    start    = time.perf_counter()
    attempts = 0
    found_pw = None

    for word in wordlist[:max_attempts]:
        attempts += 1
        if bcrypt.checkpw(word.encode(), target_hash):
            found_pw = word
            break

    elapsed = time.perf_counter() - start
    return {
        "found":       found_pw,
        "attempts":    attempts,
        "elapsed":     elapsed,
        "speed":       attempts / elapsed if elapsed > 0 else 0,
        "limited":     True,
        "max_attempts": max_attempts,
    }

def crack_argon2_limited(target_hash: str, wordlist: list[str],
                          ph: PasswordHasher,
                          max_attempts: int = MAX_ATTEMPTS_ARGON2) -> dict:
    start    = time.perf_counter()
    attempts = 0
    found_pw = None

    for word in wordlist[:max_attempts]:
        attempts += 1
        try:
            ph.verify(target_hash, word)
            found_pw = word
            break
        except VerifyMismatchError:
            pass

    elapsed = time.perf_counter() - start
    return {
        "found":        found_pw,
        "attempts":     attempts,
        "elapsed":      elapsed,
        "speed":        attempts / elapsed if elapsed > 0 else 0,
        "limited":      True,
        "max_attempts": max_attempts,
    }

def estimate_full_crack_time(speed_per_sec: float,
                              wordlist_size: int,
                              rockyou_size: int = 14_344_391) -> str:
    if speed_per_sec <= 0:
        return "N/A"
    secs_wordlist = wordlist_size / speed_per_sec
    secs_rockyou  = rockyou_size / speed_per_sec

    def fmt(s: float) -> str:
        if s < 1:      return f"{s*1000:.1f} mili-giây"
        if s < 60:     return f"{s:.2f} giây"
        if s < 3600:   return f"{s/60:.1f} phút"
        if s < 86400:  return f"{s/3600:.1f} giờ"
        return         f"{s/86400:.1f} ngày"

    return f"{fmt(secs_wordlist)} (wordlist này) | {fmt(secs_rockyou)} (rockyou 14M)"

def main():
    section("CHUẨN BỊ: Tạo hash nạn nhân")

    if USE_WORDLIST and WORDLIST_PATH:
        wordlist = load_wordlist(WORDLIST_PATH)
    else:
        wordlist = build_wordlist()
        print(f"  Dùng wordlist mặc định ({len(wordlist)} password phổ biến)")

    pw_bytes = VICTIM_PASSWORD.encode()

    hash_md5    = hashlib.md5(pw_bytes).hexdigest()
    hash_sha1   = hashlib.sha1(pw_bytes).hexdigest()
    hash_bcrypt = bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12))
    ph          = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
    hash_argon  = ph.hash(VICTIM_PASSWORD)

    print(f"  Nạn nhân dùng password : '{VICTIM_PASSWORD}'")
    print(f"  MD5    hash            : {hash_md5}")
    print(f"  SHA1   hash            : {hash_sha1}")
    print(f"  bcrypt hash            : {hash_bcrypt.decode()[:40]}...")
    print(f"  argon2 hash            : {hash_argon[:40]}...")
    print(f"\n  Kẻ tấn công có được hash từ DB bị lộ → bắt đầu crack!")

    section("TẤN CÔNG 1: Crack MD5")
    print(f"  Target hash: {hash_md5}\n")
    print("  Đang thử từng password trong wordlist...")

    r = crack_md5(hash_md5, wordlist)

    if r["found"]:
        print(f"\n  ĐÃ CRACK! Password là: '{r['found']}'")
    else:
        print(f"\n  Không tìm thấy trong wordlist này.")

    print(f"  Số lần thử   : {r['attempts']:,}")
    print(f"  Thời gian    : {r['elapsed']*1000:.2f} ms")
    print(f"  Tốc độ       : {r['speed']:,.0f} hash/giây")
    print(f"  Ước tính     : {estimate_full_crack_time(r['speed'], len(wordlist))}")

    if TEST_ALL:
        section("TẤN CÔNG 2: Crack SHA1")
        print(f"  Target hash: {hash_sha1}\n")
        r2 = crack_sha1(hash_sha1, wordlist)
        if r2["found"]:
            print(f"\n  ĐÃ CRACK! Password là: '{r2['found']}'")
        print(f"  Số lần thử : {r2['attempts']:,}")
        print(f"  Thời gian  : {r2['elapsed']*1000:.2f} ms")
        print(f"  Tốc độ     : {r2['speed']:,.0f} hash/giây")

    section(f"TẤN CÔNG 3: Crack bcrypt  (chỉ thử {MAX_ATTEMPTS_BCRYPT} password đầu)")
    print(f"  Target hash: {hash_bcrypt.decode()[:40]}...\n")
    print(f"  Đang thử {MAX_ATTEMPTS_BCRYPT} password (sẽ mất ~{MAX_ATTEMPTS_BCRYPT * 0.21:.0f} giây)...")

    r3 = crack_bcrypt_limited(hash_bcrypt, wordlist)

    if r3["found"]:
        print(f"\n  ĐÃ CRACK! Password là: '{r3['found']}'")
    else:
        print(f"\n  KHÔNG crack được sau {r3['attempts']} lần thử")

    print(f"  Số lần thử   : {r3['attempts']:,} / {len(wordlist):,}")
    print(f"  Thời gian    : {r3['elapsed']:.2f} giây")
    print(f"  Tốc độ       : {r3['speed']:.1f} hash/giây")
    print(f"  Ước tính full: {estimate_full_crack_time(r3['speed'], len(wordlist))}")

    section(f"TẤN CÔNG 4: Crack argon2id  (chỉ thử {MAX_ATTEMPTS_ARGON2} password đầu)")
    print(f"  Target hash: {hash_argon[:40]}...\n")
    print(f"  Đang thử {MAX_ATTEMPTS_ARGON2} password...")

    r4 = crack_argon2_limited(hash_argon, wordlist, ph)

    if r4["found"]:
        print(f"\n  ĐÃ CRACK! Password là: '{r4['found']}'")
    else:
        print(f"\n  KHÔNG crack được sau {r4['attempts']} lần thử")

    print(f"  Số lần thử   : {r4['attempts']:,} / {len(wordlist):,}")
    print(f"  Thời gian    : {r4['elapsed']:.2f} giây")
    print(f"  Tốc độ       : {r4['speed']:.1f} hash/giây")
    print(f"  Ước tính full: {estimate_full_crack_time(r4['speed'], len(wordlist))}")

    section("KẾT LUẬN: So sánh khả năng phòng thủ")

    rockyou = 14_344_391
    rows = [
        ("MD5",      r["speed"],  "Crack được"),
        ("bcrypt",   r3["speed"], "Bất khả thi"),
        ("argon2id", r4["speed"], "Bất khả thi"),
    ]
    if TEST_ALL:
        rows.insert(1, ("SHA1", r2["speed"], "Crack được"))

    print(f"\n  {'Thuật toán':<12} {'Tốc độ':>16} {'Crack rockyou.txt':>22} {'Kết quả':>16}")
    print(f"  {'-'*70}")
    for name, speed, verdict in rows:
        time_est = rockyou / speed if speed > 0 else float("inf")
        if time_est < 1:
            t_str = f"{time_est*1000:.0f} ms"
        elif time_est < 60:
            t_str = f"{time_est:.1f} giây"
        elif time_est < 3600:
            t_str = f"{time_est/60:.0f} phút"
        elif time_est < 86400:
            t_str = f"{time_est/3600:.0f} giờ"
        else:
            t_str = f"{time_est/86400:,.0f} ngày"
        print(f"  {name:<12} {speed:>13,.0f} h/s {t_str:>22} {verdict:>16}")

    print(f"""
    Kết luận:
     • MD5/SHA1: tốc độ cao triệu hash/giây → rockyou.txt bị crack trong vài giây
     • bcrypt  : ~{r3['speed']:.0f} hash/giây → cần hàng nghìn ngày mới hết wordlist
     • argon2  : ~{r4['speed']:.0f} hash/giây + tốn 64MB RAM/lần → GPU cũng bó tay
    """)

if __name__ == "__main__":
    main()
