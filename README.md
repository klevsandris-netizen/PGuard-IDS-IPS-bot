# PGuard-IDS-IPS-bot

PGuard - bot that can simplify and optimize processes related with network securing and developed to make web-using safer :)

## 🛠️ How it Works (The Tech Inside)
The bot combines low-level network sniffing with a modern Telegram interface:
* **Packet Sniffing:** Uses the `Scapy` library to monitor TCP traffic on critical ports (22, 80, 21, 3389).
* **Asynchronous Logic:** Built on `Aiogram 3.x` and `Asyncio` to handle network monitoring and user interactions simultaneously.
* **Active Defense:** When a threat is detected, it triggers a Telegram alert. With one tap, the bot executes `iptables` commands to drop traffic from the attacker's IP.
* **Logging & Persistence:** Every event is logged locally (`pguard_events.log`) and users are managed via a connected database (`databaseiu`).



## ✨ Key Features
* **Real-time Alerts:** Instant notifications if someone "knocks" on your monitored ports.
* **Remote Banning:** Ban malicious IPs via Telegram buttons using Linux Firewall commands.
* **Smart Filtering:** Includes an alert interval to prevent spamming from the same IP.
* **Logs Management:** Download attack history directly through the bot as a `.txt` file.
* **Emergency Commands:** Built-in help manual with instructions on how to flush `iptables` if you accidentally lock yourself out.

## 📦 Requirements & Libraries
To run this, you'll need:
- `aiogram` (Telegram Bot Framework)
- `scapy` (Packet Manipulation)
- `python-dotenv` (Secure environment variables)
- `iptables` (Linux firewall)

## 🚀 Setup
1. Clone the repo: `git clone https://github.com/your-username/PGuard.git`
2. Install requirements: `pip install -r requirements.txt`
3. Configure your `data.env` with your `BOT_TOKENPG` and `USERS_ID`.
4. **Run with sudo** (required for packet sniffing):
   ```bash
   sudo python3 main.py




This bot is developed for simplifying cyberattacks analyzing and making it easy to prevent threats directly from you Phone! Portable bot that allows you to check attacks in real time with instant Telegram alerts, banning and tracking malicious IP-adresses. Dont judge me strict please, It is my first project. :) 
