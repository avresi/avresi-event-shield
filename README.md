# Avresi EventShield — Advanced Trigger Protection for FiveM
Avresi EventShield — Automatic event encryption and trigger-injection protection system for FiveM. Features include hashed event names, timestamped signatures, rate limiting, honeypots, and automatic bans for spoofed or insecure triggers.

🔒 Overview
Avresi EventShield is a server-side security system designed to protect your FiveM server from trigger injection, event spoofing, and event spam attacks.
It automatically encrypts all registered events, verifies their authenticity with signatures and timestamps, and bans attackers automatically when abnormal behavior is detected.
This system was built with performance, compatibility, and stability in mind — fully standalone, compatible with QB-Core, Qbox, and ESX.

⚙️ Installation (2 minutes)
Place the folder inside your resources directory.
Add the following line to your server.cfg:
setr avresi_eventshield_secret RANDOM_SECURE_KEY
ensure avresi-eventshield
Restart your server — all your events will now be hashed, signed, and protected.

⚠️ Important: Never use the default secret key.
Each server must use a unique random secret, otherwise encryption and validation will fail.

🧩 Core Features

🔐 Event Hashing
Every registered event is converted into a unique hashed name.
Example:
esx_policejob:giveWeapon → __avresi_A7F3B2E1_F9E2C7D3
This makes it nearly impossible for attackers to call your events directly.
🕒 Signatures & Timestamps
Each event carries a unique signature + timestamp that expires after 30 seconds.
Any delayed or spoofed request is automatically rejected.

⚡ Rate Limiting
Each player can send a limited number of events per minute (default: 100 per 60s).
Prevents event flooding or DoS-style spam attacks.

🧠 Honeypot Detection
If a cheater calls an unencrypted/original event name, they are instantly banned.

🧩 Source Validation
The script verifies:
Is the event source valid?
Is the player connected?
Is the ped valid?
Is the source numeric and positive?
📋 Parameter Validation
Protects against payload injection by rejecting:
Function references
Oversized tables (>1000 elements)
Strings longer than 10,000 characters
🚫 Blacklist & Whitelist
Dangerous events (like ptFxEvent, explosionEvent, etc.) are blacklisted by default.
You can easily customize these lists.

🔨 Ban & Violation System
You can modify these thresholds in the violationLimits table.

🧠 How It Works (Simplified)
Each event is re-registered with a secure hash name.
When a client triggers an event, the script generates:
A timestamp
A unique cryptographic signature
The server verifies the signature and timestamp.
If validation fails → the player is flagged or banned automatically.
Events exceeding the rate limit are blocked.

⚙️ Configuration
Secret Key:
Set via server.cfg → setr avresi_eventshield_secret <random_key>
Rate Limit:
Adjustable in code (rateLimits table)
Blacklist / Whitelist:
Editable arrays inside the script
Ban System Integration:
Replace or customize the banPlayer function to fit your admin system:
exports["avresi-base"]:BanPlayer(source, reason, "trigger")

🔧 Compatibility
✅ Standalone
✅ QB-Core
✅ Qbox
✅ ESX
🧩 Works with any Lua-based event system
⚡ Lightweight (optimized for <0.05 ms)
