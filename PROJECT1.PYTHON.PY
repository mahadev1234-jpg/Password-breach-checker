
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import re
import urllib.request
import urllib.parse
import json
import threading
from urllib.error import URLError, HTTPError


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "password", "confirm", "paypal", "amazon", "apple",
    "google", "microsoft", "netflix", "support", "ebay", "wallet",
]

KNOWN_LEGIT_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}

def extract_features(url: str) -> dict:
    """Extract heuristic features from a URL."""
    features = {}

    # Has IP address instead of domain
    features["has_ip"] = bool(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url))

    # Excessive subdomains (3+)
    try:
        domain_part = re.sub(r"https?://", "", url).split("/")[0]
        features["excess_subdomains"] = domain_part.count(".") >= 3
    except Exception:
        features["excess_subdomains"] = False

    # URL is very long
    features["long_url"] = len(url) > 75

    # Contains @
    features["has_at_symbol"] = "@" in url

    # Double slash after protocol
    features["double_slash_redirect"] = "//" in url[7:]

    # Hyphen in domain
    try:
        domain_part = re.sub(r"https?://", "", url).split("/")[0]
        features["hyphen_in_domain"] = "-" in domain_part
    except Exception:
        features["hyphen_in_domain"] = False

    # Suspicious keywords
    url_lower = url.lower()
    features["suspicious_keywords"] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
    )

    # HTTPS check
    features["no_https"] = not url.lower().startswith("https")

    # Excessive dots
    features["many_dots"] = url.count(".") > 4

    # Short URL services
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
    features["is_shortened"] = any(s in url_lower for s in shorteners)

    # Hexadecimal encoding
    features["hex_encoding"] = "%" in url

    return features


def score_url(features: dict) -> tuple[int, str, list]:
    """Score a URL based on extracted features. Returns (score, label, reasons)."""
    score = 0
    reasons = []

    if features["has_ip"]:
        score += 30
        reasons.append("⚠️ Uses raw IP address instead of domain name")
    if features["excess_subdomains"]:
        score += 20
        reasons.append("⚠️ Excessive subdomains detected")
    if features["long_url"]:
        score += 10
        reasons.append("⚠️ URL is unusually long")
    if features["has_at_symbol"]:
        score += 25
        reasons.append("⚠️ URL contains '@' (may redirect to a different host)")
    if features["double_slash_redirect"]:
        score += 15
        reasons.append("⚠️ Double slash redirect detected")
    if features["hyphen_in_domain"]:
        score += 10
        reasons.append("⚠️ Hyphen in domain (common phishing trick)")
    if features["suspicious_keywords"] >= 2:
        score += features["suspicious_keywords"] * 8
        reasons.append(f"⚠️ {features['suspicious_keywords']} suspicious keywords found")
    elif features["suspicious_keywords"] == 1:
        score += 5
        reasons.append("⚠️ 1 suspicious keyword found")
    if features["no_https"]:
        score += 20
        reasons.append("⚠️ URL does not use HTTPS")
    if features["many_dots"]:
        score += 15
        reasons.append("⚠️ Unusually many dots in URL")
    if features["is_shortened"]:
        score += 20
        reasons.append("⚠️ URL uses a known shortening service (destination unknown)")
    if features["hex_encoding"]:
        score += 10
        reasons.append("⚠️ Hex/percent encoding detected")

    score = min(score, 100)

    if score >= 60:
        label = "🚨 HIGH RISK — Likely Phishing"
    elif score >= 30:
        label = "⚠️  MODERATE RISK — Suspicious URL"
    else:
        label = "✅ LOW RISK — Appears Safe"

    return score, label, reasons


# ─────────────────────────────────────────────
# HAVEIBEENPWNED PASSWORD CHECK (k-anonymity)
# ─────────────────────────────────────────────

def check_password_breach(password: str) -> tuple[bool, int]:
    """
    Check password against HaveIBeenPwned using k-anonymity.
    Only the first 5 chars of the SHA1 hash are sent — never the full password.
    Returns (found, count).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityCheckerApp/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8")
    except (URLError, HTTPError) as e:
        raise ConnectionError(f"Could not reach HaveIBeenPwned API: {e}")

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return True, int(parts[1])

    return False, 0

class SecurityCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Checker")
        self.geometry("780x780")
        self.resizable(True, True)
        self.configure(bg="#0d0f14")
        self._build_ui()

    # ── Styles ──────────────────────────────
    COLORS = {
        "bg":        "#0d0f14",
        "panel":     "#13161e",
        "border":    "#1e2330",
        "accent":    "#00d4ff",
        "accent2":   "#7c3aed",
        "text":      "#e2e8f0",
        "subtext":   "#64748b",
        "safe":      "#22c55e",
        "warn":      "#f59e0b",
        "danger":    "#ef4444",
        "entry_bg":  "#1a1d27",
    }

    def _build_ui(self):
        c = self.COLORS
        pad = {"padx": 24, "pady": 8}

        
        hdr = tk.Frame(self, bg=c["bg"])
        hdr.pack(fill="x", padx=30, pady=(28, 6))

        tk.Label(
            hdr, text="🔐 Security Checker",
            font=("Courier New", 22, "bold"),
            fg=c["accent"], bg=c["bg"]
        ).pack(side="left")

        tk.Label(
            hdr, text="Phishing URL Detector  ·  Password Breach Checker",
            font=("Courier New", 10),
            fg=c["subtext"], bg=c["bg"]
        ).pack(side="left", padx=16, pady=(6, 0))

        ttk.Separator(self).pack(fill="x", padx=20, pady=4)

    
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=c["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
            background=c["panel"], foreground=c["subtext"],
            font=("Courier New", 11, "bold"),
            padding=[18, 8], borderwidth=0)
        style.map("TNotebook.Tab",
            background=[("selected", c["border"])],
            foreground=[("selected", c["accent"])])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=10)

        tab1 = tk.Frame(nb, bg=c["bg"])
        tab2 = tk.Frame(nb, bg=c["bg"])
        nb.add(tab1, text="  🔗 URL Checker  ")
        nb.add(tab2, text="  🔑 Password Checker  ")

        self._build_url_tab(tab1)
        self._build_password_tab(tab2)

    # ── URL Tab ─────────────────────────────
    def _build_url_tab(self, parent):
        c = self.COLORS

        tk.Label(parent,
            text="Paste a URL to analyse it for phishing indicators.",
            font=("Courier New", 10), fg=c["subtext"], bg=c["bg"]
        ).pack(anchor="w", padx=24, pady=(16, 6))

        entry_frame = tk.Frame(parent, bg=c["border"], bd=0)
        entry_frame.pack(fill="x", padx=24, pady=(0, 10))

        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(
            entry_frame, textvariable=self.url_var,
            font=("Courier New", 12), bg=c["entry_bg"],
            fg=c["text"], insertbackground=c["accent"],
            relief="flat", bd=8
        )
        self.url_entry.pack(fill="x")
        self.url_entry.bind("<Return>", lambda e: self._check_url())

        self.url_btn = tk.Button(
            parent, text="Analyse URL",
            font=("Courier New", 12, "bold"),
            bg=c["accent"], fg="#000", activebackground="#00b8e0",
            relief="flat", cursor="hand2", padx=20, pady=10,
            command=self._check_url
        )
        self.url_btn.pack(pady=6)

        # Result panel
        self.url_result_frame = tk.Frame(parent, bg=c["panel"], bd=1, relief="flat")
        self.url_result_frame.pack(fill="both", expand=True, padx=24, pady=(8, 20))

        self.url_score_label = tk.Label(
            self.url_result_frame, text="",
            font=("Courier New", 16, "bold"),
            bg=c["panel"], fg=c["text"], wraplength=680, justify="left"
        )
        self.url_score_label.pack(anchor="w", padx=16, pady=(16, 4))

        self.url_bar_canvas = tk.Canvas(
            self.url_result_frame, height=14, bg=c["panel"],
            highlightthickness=0
        )
        self.url_bar_canvas.pack(fill="x", padx=16, pady=(0, 10))

        self.url_reasons_text = tk.Text(
            self.url_result_frame,
            font=("Courier New", 10), bg=c["panel"], fg=c["text"],
            relief="flat", state="disabled", height=10,
            wrap="word", padx=12, pady=8,
            selectbackground=c["border"]
        )
        self.url_reasons_text.pack(fill="both", expand=True, padx=4, pady=(0, 12))

    def _check_url(self):
        c = self.COLORS
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input needed", "Please enter a URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        features = extract_features(url)
        score, label, reasons = score_url(features)

        
        if score >= 60:
            colour = c["danger"]
        elif score >= 30:
            colour = c["warn"]
        else:
            colour = c["safe"]

        self.url_score_label.config(
            text=f"{label}   [{score}/100]", fg=colour
        )

    
        self.url_bar_canvas.update_idletasks()
        w = self.url_bar_canvas.winfo_width()
        self.url_bar_canvas.delete("all")
        self.url_bar_canvas.create_rectangle(0, 0, w, 14, fill=self.COLORS["border"], outline="")
        self.url_bar_canvas.create_rectangle(0, 0, int(w * score / 100), 14, fill=colour, outline="")

        # Reasons
        self.url_reasons_text.config(state="normal")
        self.url_reasons_text.delete("1.0", "end")
        if reasons:
            self.url_reasons_text.insert("end", "\n".join(reasons))
        else:
            self.url_reasons_text.insert("end", "✅ No phishing indicators detected.")
        self.url_reasons_text.config(state="disabled")

    def _build_password_tab(self, parent):
        c = self.COLORS

        tk.Label(parent,
            text="Check if your credentials appear in known data breaches.\nYour password is NEVER sent — only an anonymous hash prefix.",
            font=("Courier New", 10), fg=c["subtext"], bg=c["bg"],
            justify="left"
        ).pack(anchor="w", padx=24, pady=(16, 6))

        # Email
        tk.Label(parent, text="Email address",
            font=("Courier New", 10, "bold"), fg=c["subtext"], bg=c["bg"]
        ).pack(anchor="w", padx=24)

        self.email_var = tk.StringVar()
        ef = tk.Frame(parent, bg=c["border"])
        ef.pack(fill="x", padx=24, pady=(2, 10))
        tk.Entry(ef, textvariable=self.email_var,
            font=("Courier New", 12), bg=c["entry_bg"],
            fg=c["text"], insertbackground=c["accent"],
            relief="flat", bd=8
        ).pack(fill="x")

        # Password
        tk.Label(parent, text="Password",
            font=("Courier New", 10, "bold"), fg=c["subtext"], bg=c["bg"]
        ).pack(anchor="w", padx=24)

        self.pw_var = tk.StringVar()
        pf = tk.Frame(parent, bg=c["border"])
        pf.pack(fill="x", padx=24, pady=(2, 10))
        self.pw_entry = tk.Entry(pf, textvariable=self.pw_var,
            font=("Courier New", 12), bg=c["entry_bg"],
            fg=c["text"], insertbackground=c["accent"],
            relief="flat", bd=8, show="•"
        )
        self.pw_entry.pack(fill="x")

        # Show/hide toggle
        self.show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="Show password",
            variable=self.show_pw, command=self._toggle_pw,
            font=("Courier New", 9), fg=c["subtext"], bg=c["bg"],
            activebackground=c["bg"], selectcolor=c["border"]
        ).pack(anchor="w", padx=24, pady=(0, 6))

        self.pw_btn = tk.Button(
            parent, text="Check Breach Status",
            font=("Courier New", 12, "bold"),
            bg=c["accent2"], fg="#fff", activebackground="#6d28d9",
            relief="flat", cursor="hand2", padx=20, pady=10,
            command=self._check_password
        )
        self.pw_btn.pack(pady=6)

        # Spinner label
        self.pw_status = tk.Label(parent, text="",
            font=("Courier New", 10, "italic"),
            fg=c["subtext"], bg=c["bg"]
        )
        self.pw_status.pack()

        # Result panel
        self.pw_result_frame = tk.Frame(parent, bg=c["panel"])
        self.pw_result_frame.pack(fill="both", expand=True, padx=24, pady=(8, 20))

        self.pw_result_label = tk.Label(
            self.pw_result_frame, text="",
            font=("Courier New", 14, "bold"),
            bg=c["panel"], fg=c["text"],
            wraplength=680, justify="left"
        )
        self.pw_result_label.pack(anchor="w", padx=16, pady=(16, 8))

        self.pw_detail_label = tk.Label(
            self.pw_result_frame, text="",
            font=("Courier New", 10),
            bg=c["panel"], fg=c["subtext"],
            wraplength=680, justify="left"
        )
        self.pw_detail_label.pack(anchor="w", padx=16, pady=(0, 16))

    def _toggle_pw(self):
        self.pw_entry.config(show="" if self.show_pw.get() else "•")

    def _check_password(self):
        c = self.COLORS
        email = self.email_var.get().strip()
        password = self.pw_var.get()

        if not email or not password:
            messagebox.showwarning("Input needed", "Please enter both email and password.")
            return

        self.pw_btn.config(state="disabled")
        self.pw_status.config(text="⏳ Querying HaveIBeenPwned …")
        self.pw_result_label.config(text="")
        self.pw_detail_label.config(text="")

        def run():
            try:
                found, count = check_password_breach(password)
                self.after(0, lambda: self._show_pw_result(email, found, count))
            except ConnectionError as e:
                self.after(0, lambda: self._show_pw_error(str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _show_pw_result(self, email, found, count):
        c = self.COLORS
        self.pw_btn.config(state="normal")
        self.pw_status.config(text="")

        if found:
            self.pw_result_label.config(
                text=f"🚨 PASSWORD COMPROMISED",
                fg=c["danger"]
            )
            self.pw_detail_label.config(
                text=(
                    f"The password entered for {email} has appeared in\n"
                    f"{count:,} known data breach(es).\n\n"
                    "ACTION REQUIRED:\n"
                    "  • Change this password immediately on all sites where it's used.\n"
                    "  • Use a unique, randomly generated password.\n"
                    "  • Enable two-factor authentication where possible."
                ),
                fg=c["warn"]
            )
        else:
            self.pw_result_label.config(
                text="✅ Password Not Found in Breaches",
                fg=c["safe"]
            )
            self.pw_detail_label.config(
                text=(
                    f"Good news! The password for {email} was not found\n"
                    "in HaveIBeenPwned's database of known breaches.\n\n"
                    "Still recommended:\n"
                    "  • Use a unique password for every account.\n"
                    "  • Enable two-factor authentication.\n"
                    "  • Check periodically as breach databases grow."
                ),
                fg=c["subtext"]
            )

    def _show_pw_error(self, msg):
        self.pw_btn.config(state="normal")
        self.pw_status.config(text="")
        messagebox.showerror("API Error", msg)

if __name__ == "__main__":
    app = SecurityCheckerApp()
    app.mainloop()