import hashlib
import time
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

PASSWORD     = "MyPassword123"
WRONG_PASS   = "WrongPassword"
BCRYPT_COST  = 12
REPEAT       = 10

def section(title: str) -> None:
    print(f"\n{'='*55}")
    print(f"  {title}")
    print('='*55)

def avg_ms(fn, repeat=REPEAT) -> tuple[float, any]:
    result = None
    start  = time.perf_counter()
    for _ in range(repeat):
        result = fn()
    elapsed = (time.perf_counter() - start) / repeat * 1000
    return elapsed, result

section("1. THUẬT TOÁN KHÔNG AN TOÀN (MD5 · SHA1 · SHA256)")

password_bytes = PASSWORD.encode()

for algo in ["md5", "sha1", "sha256"]:
    ms, digest = avg_ms(
        lambda a=algo: hashlib.new(a, password_bytes).hexdigest()
    )
    print(f"\n  [{algo.upper():>6}]")
    print(f"    Hash   : {digest}")
    print(f"    Thời gian: {ms:.4f} ms  (trung bình {REPEAT} lần)")
    print(f"    Salt   : KHÔNG có – cùng password → cùng hash!")
md5_1 = hashlib.md5(password_bytes).hexdigest()
md5_2 = hashlib.md5(password_bytes).hexdigest()
print(f"\n  Hash lần 1 == Hash lần 2 ? {md5_1 == md5_2}")

section(f"2. BCRYPT  (cost factor = {BCRYPT_COST})")

ms_hash, hashed_bcrypt = avg_ms(
    lambda: bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=BCRYPT_COST))
)
print(f"\n  Hash    : {hashed_bcrypt.decode()}")
print(f"  Thời gian hash: {ms_hash:.1f} ms  (trung bình {REPEAT} lần)")

hash_b2 = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=BCRYPT_COST))
print(f"\n  Hash lần 1 == Hash lần 2 ? {hashed_bcrypt == hash_b2}")

correct = bcrypt.checkpw(password_bytes, hashed_bcrypt)
wrong   = bcrypt.checkpw(WRONG_PASS.encode(), hashed_bcrypt)
print(f"\n  Verify đúng password  : {correct}")
print(f"  Verify sai password   : {wrong}")

section("3. ARGON2id  (memory-hard – winner PHC 2015)")

ph = PasswordHasher(
    time_cost    = 2,
    memory_cost  = 65536,
    parallelism  = 2,
    hash_len     = 32,
    salt_len     = 16,
)

ms_hash, hashed_argon = avg_ms(lambda: ph.hash(PASSWORD))
print(f"\n  Hash    : {hashed_argon}")
print(f"  Thời gian hash: {ms_hash:.1f} ms  (trung bình {REPEAT} lần)")
print(f"\n  Giải thích tham số:")
parts = hashed_argon.split("$")
print(f"    $argon2id  = thuật toán")
print(f"    v=         = version")
print(f"    m=65536    = 64 MB memory cost")
print(f"    t=2        = time cost")
print(f"    p=2        = parallelism")

try:
    ph.verify(hashed_argon, PASSWORD)
    print(f"\n  Verify đúng password  : True")
except VerifyMismatchError:
    print(f"\n  Verify đúng password  : False")

try:
    ph.verify(hashed_argon, WRONG_PASS)
    print(f"  Verify sai password   : True")
except VerifyMismatchError:
    print(f"  Verify sai password   : False")

section("4. BẢNG TỔNG KẾT")

results = {}
results["MD5"]      = avg_ms(lambda: hashlib.md5(password_bytes).hexdigest())[0]
results["SHA1"]     = avg_ms(lambda: hashlib.sha1(password_bytes).hexdigest())[0]
results["SHA256"]   = avg_ms(lambda: hashlib.sha256(password_bytes).hexdigest())[0]
results["bcrypt"]   = avg_ms(lambda: bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=BCRYPT_COST)))[0]
results["argon2id"] = avg_ms(lambda: ph.hash(PASSWORD))[0]

print(f"\n  {'Thuật toán':<12} {'Thời gian TB':>14} {'Có salt':>8} {'An toàn':>8}")
print(f"  {'-'*46}")
rows = [
    ("MD5",      results["MD5"],      "Không", ""),
    ("SHA1",     results["SHA1"],     "Không", ""),
    ("SHA256",   results["SHA256"],   "Không", ""),
    ("bcrypt",   results["bcrypt"],   "Có",    ""),
    ("argon2id", results["argon2id"], "Có",    ""),
]
for name, ms, salt, safe in rows:
    print(f"  {name:<12} {ms:>11.2f} ms {salt:>8} {safe:>8}")

slowest = max(results["bcrypt"], results["argon2id"])
fastest = min(results["MD5"], results["SHA1"])
print(f"\n  → bcrypt/argon2 chậm hơn MD5 khoảng {slowest/fastest:,.0f}x")
