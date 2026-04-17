# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered the user "employee" on `windows-vm-1` downloaded a TOR installer, executed it (resulting in many TOR-related files being written to the Desktop), and subsequently created a file called `tor-shopping-list.txt` on the Desktop at `2026-04-16T20:41:47Z`. The earliest TOR-related file event was a FileRenamed on the installer at `2026-04-16T20:30:03Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-vm-1"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-16T20:30:03.385996Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![DeviceFileEvents query results showing tor-related file activity](query-4.png)

---

### 2. Searched the `DeviceProcessEvents` Table for Installer Execution

Searched for any `ProcessCommandLine` that contained the string "tor-browser". Based on the log returned, at `2026-04-16T20:34:23Z`, the user "employee" on `windows-vm-1` ran the file `tor-browser-windows-x86_64-portable-15.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

Installer SHA256: `2f7dea5cb68c538ed0cf...`

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-1"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

![DeviceProcessEvents query result showing silent installation of TOR Browser](query-3.png)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. Evidence confirms the browser was opened at `2026-04-16T20:34:57Z`, when `tor.exe` was spawned. Several instances of `firefox.exe` (TOR Browser's bundled Firefox) content processes were observed spawning immediately before and after, consistent with normal TOR Browser startup behavior.

Observed SHA256 values:
- `tor.exe`: `176c9cb6131fb49fa5e9...`
- `firefox.exe`: `ef09a491d65b51f1f304...`

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-1"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

![DeviceProcessEvents query results showing tor.exe and firefox.exe process creation](query-2.png)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection over known TOR ports. At `2026-04-16T20:35:04Z`, the user "employee" on `windows-vm-1` successfully established a connection to the remote IP address `150.230.22.185` on port `9001` via `tor.exe`. Additional outbound connections over port `9001` to multiple TOR guard/relay nodes followed, and at `2026-04-16T20:35:26Z`, `firefox.exe` connected to the local TOR SOCKS proxy at `127.0.0.1:9150`, confirming the browser was routing traffic through the TOR network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-vm-1"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

![DeviceNetworkEvents query results showing outbound TOR connections](query-1.png)

---

## Chronological Event Timeline

### 1. File Download - TOR Installer

- **Timestamp:** `2026-04-16T20:30:03Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.9.exe` to the Downloads folder (FileRenamed event, typical of browser download completion).
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`
- **SHA256:** `2f7dea5cb68c538ed0cf...`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-04-16T20:34:23Z`
- **Event:** The user "employee" executed the installer in silent mode, initiating a background installation of the TOR Browser with no user-facing prompts.
- **Action:** Process creation detected.
- **Command:** `"tor-browser-windows-x86_64-portable-15.0.9.exe" /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 3. File Creation - TOR Browser Files Written to Desktop

- **Timestamps:**
  - `2026-04-16T20:34:31Z` - `Tor-Launcher.txt`, `Torbutton.txt`, `tor.txt` created on Desktop
  - `2026-04-16T20:34:32Z` - `tor.exe` created at `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
  - `2026-04-16T20:34:35Z` - `Tor Browser.lnk` shortcut created on Desktop
- **Event:** The silent installer unpacked TOR Browser portable files to the Desktop.
- **Action:** Multiple file creation events detected.

### 4. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-16T20:34:57Z`
- **Event:** The user "employee" launched TOR Browser. `tor.exe` was spawned and multiple `firefox.exe` content processes were created between `20:34:56Z` and `20:34:59Z`, consistent with normal TOR Browser startup (parent browser, TOR daemon, and child tab/content processes).
- **Action:** Process creation of TOR Browser executables detected.
- **Process Paths:**
  - `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` (SHA256: `176c9cb6131fb49fa5e9...`)
  - `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe` (SHA256: `ef09a491d65b51f1f304...`)

### 5. Network Connection - TOR Guard/Relay Node

- **Timestamp:** `2026-04-16T20:35:04Z`
- **Event:** `tor.exe` established a connection to `150.230.22.185` on port `9001`, a well-known TOR ORPort used for relay-to-relay and client-to-guard communication. This confirms the device joined the TOR network.
- **Action:** ConnectionSuccess.
- **Process:** `tor.exe`

### 6. Additional Network Connections - TOR Circuit Activity

- **Timestamps:**
  - `2026-04-16T20:35:05Z` - Connection to `150.230.22.185:9001`
  - `2026-04-16T20:35:07Z` - Connection to `46.226.111.65:9001` (with RemoteUrl `https://www.7nrposwrg...`)
  - `2026-04-16T20:35:26Z` - **firefox.exe** connection to `127.0.0.1:9150` (local TOR SOCKS proxy)
  - `2026-04-16T20:36:09Z` - Connections to `45.137.199.102:9001` and `192.121.108.175:9001`
  - `2026-04-16T20:36:12Z` - Connection to `192.121.108.175:9001`
  - `2026-04-16T20:37:08Z` - Connection to `45.137.199.102:9001`
- **Event:** Multiple outbound connections to TOR relay nodes on port 9001, plus the local SOCKS proxy handoff from `firefox.exe` to `tor.exe`, confirm an active TOR browsing session.
- **Action:** Multiple successful connections detected.

### 7. File Creation - TOR Shopping List

- **Timestamps:**
  - `2026-04-16T20:41:47Z` - `tor-shopping-list.txt` renamed/created on Desktop
  - `2026-04-16T20:43:16Z` - `tor-shopping-list.txt` modified
- **Event:** The user "employee" created and subsequently edited a file named `tor-shopping-list.txt` on the Desktop, potentially indicating notes or a list of items related to their TOR browser activities.
- **Action:** File creation and modification detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the `windows-vm-1` device downloaded and silently installed the TOR Browser portable version 15.0.9, then launched the browser, established multiple connections to TOR guard and relay nodes on port 9001, and routed browser traffic through the local TOR SOCKS proxy on port 9150. Approximately seven minutes after the browser first connected to the TOR network, the user created a file named `tor-shopping-list.txt` on the Desktop and modified it shortly after. The sequence of activities, combined with the use of the `/S` silent-install flag to suppress installer prompts, indicates the user actively and deliberately installed, configured, and used the TOR browser for anonymous browsing.

All observed activity is attributable to a single user account (`employee`) on a single endpoint (`windows-vm-1`). The contents of the user's TOR browsing sessions cannot be reconstructed from network logs alone.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-vm-1` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
