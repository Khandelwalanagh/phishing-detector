import urllib.request, json, sys

BASE = "http://localhost:8000"

def post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

# ── Test 1: Phishing URL ───────────────────────────────────────
r1 = post("/api/check-url", {"url": "http://paypal-secure-login.tk/verify/account?update=true"})
print("=== URL Test (phishing) ===")
print(f"  risk_score : {r1['risk_score']}")
print(f"  label      : {r1['label']}")
print(f"  confidence : {r1['confidence']}")
print(f"  signals    : {len(r1['reasons'])}")
for s in r1["reasons"][:4]:
    print(f"    - {s}")

print()

# ── Test 2: Legitimate URL ─────────────────────────────────────
r2 = post("/api/check-url", {"url": "https://www.google.com/search?q=weather"})
print("=== URL Test (legitimate) ===")
print(f"  risk_score : {r2['risk_score']}")
print(f"  label      : {r2['label']}")
print(f"  confidence : {r2['confidence']}")

print()

# ── Test 3: Phishing email ─────────────────────────────────────
body = (
    "Dear Customer, your account has been suspended due to unusual activity. "
    "Please click here immediately to verify: http://paypal.com.login.tk/verify?user=abc "
    "or your account will be permanently closed. Update your password and billing info now."
)
r3 = post("/api/check-email", {"content": body})
print("=== Email Test (phishing) ===")
print(f"  risk_score : {r3['risk_score']}")
print(f"  label      : {r3['label']}")
print(f"  signals    : {len(r3['reasons'])}")
for s in r3["reasons"][:4]:
    print(f"    - {s}")

print()

# ── Test 4: Clean email ────────────────────────────────────────
clean = "Hi John, just following up on our meeting scheduled for Friday at 10am. Let me know if that still works for you. Best, Sarah"
r4 = post("/api/check-email", {"content": clean})
print("=== Email Test (clean) ===")
print(f"  risk_score : {r4['risk_score']}")
print(f"  label      : {r4['label']}")

print()
print("All tests passed!")
sys.exit(0)
