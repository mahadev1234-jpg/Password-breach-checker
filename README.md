How the Password Breach Checker Works
It uses the HaveIBeenPwned (HIBP) k-anonymity API — cleverly designed so your real password never leaves your machine.
The 3-Step Process
1. Hash the password locally
The password is converted to a SHA-1 hash entirely on your device:
password123 → CBFDAC6008F9CAB4083784CBD1874F76618D2A97
2. Send only the first 5 characters
Only CBFDA is sent to the HIBP API. This is called k-anonymity — the server has no idea what your actual password is, just a tiny fragment of its hash.
3. Match locally
HIBP returns ~800 hash suffixes that start with CBFDA. The app then checks if your full hash suffix (C6008F9CAB4083784CBD1874F76618D2A97) is in that list — entirely on your device. If matched, it also returns the breach count.
Why this is safe
The 5-char prefix maps to thousands of possible passwords, so HIBP can't reverse-engineer yours. Your actual password or full hash is never transmitted.
What happens in the UI
A background thread handles the API call so the UI doesn't freeze
If found → shows breach count + urgent action steps
If not found → confirms safety + best-practice reminders
Any network failure is caught and shown as a clean error message
