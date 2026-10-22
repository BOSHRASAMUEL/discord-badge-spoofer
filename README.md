# 🎮 Discord Science Spoofer - Modern UI Edition

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-5.2.0-blueviolet?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **Note:** This project is a **Fork** of the original [discord-badge-spoofer](https://github.com/revere-group/discord-badge-spoofer) created by **Revere Group**. 
> All credit for the core logic, backend, and PowerShell fingerprinting goes to them. This version adds a Graphical User Interface (GUI) and improves the overall user experience.

A powerful, modern Graphical User Interface (GUI) wrapper for the Discord Science Spoofer. Built with **CustomTkinter**, this tool simulates game launches and heartbeats to Discord's science endpoint, allowing you to inflate your **Games Played** and **Hours Played** badges.

---

## ✨ Features (UI & Core)

* 🎨 **Modern Discord-Style UI**: A fully responsive, dark-themed interface inspired by Discord's native design. It dynamically adapts to any window size (with a minimum size lock to prevent UI overlapping).
* 🧵 **Non-Blocking Threading**: All network requests, game loading, and spoofing processes run in the background, ensuring the UI never freezes or hangs.
* 📁 **File Picker Integration**: Generate executable fingerprints directly from the UI using a built-in file browser to easily select your `.exe` files.
* 🖥️ **Built-in Console**: Watch the logs in real-time directly within the app—no need to keep the terminal open.
* ⚡ **Batch Processing**: Sends events in chunks (50 games per request) to avoid rate limits and ensure a smooth experience.
* 🔐 **State Management**: Automatically saves and loads your Token, Cookie, and Fingerprint securely in `science_state.json`.
* 🔗 **Quick Links**: Auto-opens the GitHub repository on startup to encourage starring, and includes a "Contact Me" button.

---

## 📦 Prerequisites

Before running the application, ensure you have Python installed (3.10 or newer is recommended) and install the required dependency:

```bash
pip install customtkinter
```

---

## 🚀 Usage

1. Clone the repository or download the source code.
2. Open your terminal in the project folder.
3. Run the main script:
   ```bash
   python spoofer.py
   ```
4. **In the UI:**
   * Paste your Discord **Account Token** and **cf_clearance Cookie**.
   * *(Optional but recommended)* Select a game's `.exe` file and click **Generate Fingerprint**.
   * Enter the number of games and hours per game.
   * Click **START SPOOFING** and watch the logs!

---

## 🏆 Credits & Ownership

This project is the result of combining powerful core logic with a modern user interface.

| Role | Author / Project |
| :--- | :--- |
| **Core Logic & Backend (Original)** | [Revere Group](https://github.com/revere-group) |
| **GUI Design & Frontend** | **Bisho (BOSHRASAMUEL)** |

### Ownership Notes:
* **The Backend / Core Logic**: The original Python script (`spoofer.py`), API request structures, fingerprint generation (PowerShell), and Discord bypass logic belong to **Revere Group** under the MIT License.
* **The GUI / Frontend**: The CustomTkinter graphical interface, thread management, console redirection, responsive layout, user experience design, and additional features were developed and integrated by **Bisho**.
* *If you are the original author and wish for this UI adaptation to be taken down, please contact me.*

---

## ⚠️ Disclaimer

**This tool is for educational purposes only.** 
Using this script violates Discord's Terms of Service (ToS). Spoofing badges may result in account termination or a permanent ban. The developer of this UI takes no responsibility for any actions taken against your account. **Use this at your own risk.**
