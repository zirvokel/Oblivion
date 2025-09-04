# Oblivion

> **Oblivion** is a controlled and automated file transfer solution between two completely isolated Active Directory domains, through a secured Linux gateway.

---

## 🚀 Overview

In sensitive environments (banks, administrations, critical infrastructures), multiple **Active Directory** domains may exist in complete isolation from one another.

The question becomes: *how can an authorized user securely transfer a file between these walled-off worlds?*

**Oblivion** answers that question.

It acts as a **Linux relay**, automating file transfers between two distinct domains without ever opening direct communication between them.

Transfers rely on a simple yet secure **IN/OUT folder model**, synchronized by a robust background service.

---

## 📐 Architecture

* **DOM1** : `192.168.10.0/24`

  * Domain Controller: `192.168.10.2`
  * Accounts suffixed with `.dmz`

* **DOM2** : `10.10.240.0/24`

  * Domain Controller: `10.10.240.2`
  * Accounts suffixed with `.adm`

* **Oblivion Gateway (Linux)** :

  * DOM1 Interface: `192.168.10.1`
  * DOM2 Interface: `10.10.240.1`
  * Synchronization service via `systemd` every **10 seconds**

Each authorized user is given two transactional directories:

```
Transactions/
└── user.suffix/
    ├── IN   # Files to send to the other domain
    └── OUT  # Files received from the other domain
```

---

## 🔧 How It Works

1. **User Creation**

   * Accounts automatically provisioned via PowerShell (`dc1.ps1` / `dc2.ps1`)
   * Added to the security group `DMZ_2_ADM`
   * `IN` and `OUT` directories created with strict ACLs

2. **Linux Relay**

   * Mounts each domain’s `Transactions` share via **CIFS**
   * Runs `/usr/local/sbin/ftbridge_sync.sh` as a `systemd` service
   * Performs **bidirectional synchronization** every 10 seconds
   * Detailed logs available in `/var/log/ftbridge/sync.log`

3. **File Transfer**

   * Stable files placed in `IN` → automatically copied to `OUT` in the other domain
   * File stability validated via size consistency check

---

## ⚙️ Installation

### 1. On each Domain Controller (DC1 & DC2)

Run the appropriate PowerShell script:

```powershell
.\dc1.ps1   # On DOM1
.\dc2.ps1   # On DOM2
```

These scripts:

* Create the `DMZ_2_ADM` group
* Configure the `Transactions` share
* Apply ACLs
* Provision service accounts (`svc_relay_dom1`, `svc_relay_dom2`)

---

### 2. On the Linux Gateway

Download and run the installer:

```bash
curl -o /opt/setup_relay.sh https://github.com/<ORG>/oblivion/setup_relay.sh
chmod +x /opt/setup_relay.sh
sudo /opt/setup_relay.sh
```

The script will:

* Configure network interfaces
* Install dependencies (`rsync`, `cifs-utils`, `smbclient`)
* Mount `Transactions` shares
* Deploy `ftbridge_sync.sh`
* Set up a **systemd service + timer (10s)**

---

## 📊 Logging

All transfers are logged, e.g.:

```
[2025-09-04 11:02:13] === CYCLE ===
[2025-09-04 11:02:13] DOM1->DOM2 : j.doe.dmz/IN -> j.doe.adm/OUT
[2025-09-04 11:02:13] DOM2->DOM1 : f.golgo.adm/IN -> f.golgo.dmz/OUT
```

Logs are stored in:

```
/var/log/ftbridge/sync.log
```

---

## 🔒 Security

* **No routing** between DOM1 and DOM2 (`net.ipv4.ip_forward=0`)
* **Strict isolation** via per-user directories
* **Windows ACLs** ensure only the user and relay service can access files
* **Controlled relay** → never direct network access between domains

---

## 🛠️ Roadmap

* [x] Fixed and reliable bidirectional sync
* [x] User management and permission fixes
* [ ] Integration of **ClamAV** for antivirus scanning
* [ ] Linux hardening (**firewall, minimal services**)
* [ ] Enhanced logging verbosity and traceability
* [ ] File **queue system** to handle copy operations
* [ ] Automatic **ClamAV report** dropped in the user’s `OUT` folder
* [ ] Configurable **unidirectional/bidirectional** sync modes
* [ ] Production-ready deployment documentation
* [ ] (Future) Web-based **GUI dashboard** for easier administration

---

## 📝 License

Distributed under the **Apache 2.0 License**.
See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome!

Please:

1. Fork the repo
2. Create a branch (`feature/my-feature`)
3. Submit a detailed PR

---

## 👨‍💻 Authors

* **Fede**
