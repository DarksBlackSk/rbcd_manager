# rbcd_manager

rbcd_manager is a .NET tool designed to enumerate and configure Resource-Based Constrained Delegation (RBCD) in Active Directory domains.

* The tool includes:

1. ✔️ Configuration mode — Modifies the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor to add a computer account.
2. ✔️ Verification mode — Scans all domain computers and detects RBCD permissions granted to principals other than SELF.
3. ✔️ Works using the current security context (Kerberos / Negotiate).

It is useful for System Administrators, Blue Teams, Auditors, and Red Team labs.

---

# 🔧 Usage

## 1) Configuration Mode

Adds an attacker/authorized computer to the RBCD ACL of a target computer.

```powershell
rbcd_manager.exe <target_computer> <attacker_computer> <domain>
```

Example:

```powershell
rbcd_manager.exe lon-cs-1 lon-wkstn-1 CONTOSO.COM
```
<img width="1657" height="445" alt="image" src="https://github.com/user-attachments/assets/766982f2-6210-434f-b333-cfeeb6bc0b75" />

## 2) Verification Mode

Scans all domain computers and displays which ones have non-default RBCD entries.

```powershell
rbcd_manager.exe -verify <domain>
```

Example:

```powershell
rbcd_manager.exe -verify CONTOSO.COM
```

<img width="779" height="871" alt="Screenshot From 2025-12-03 12-33-00" src="https://github.com/user-attachments/assets/1c2ee19f-368f-4a45-94f0-16f33e2d42eb" />

## 3) List RBCD Configurations

```powershell
rbcd_manager.exe -list <domain>
```


## 4) Create Computer Account

```powershell
rbcd_manager.exe -create <computer_name> <domain> [password]
```

* When a password is not specified, a random one will be generated and the user will be informed aboud it

```powershell
rbcd_manager.exe -create <computer_name> <domain>
```

## 5) Remove RBCD Configuration 

* Remove a specific machine from the configuration list in <target_computer>

```powershell
rbcd_manager.exe -remove <target_computer> <domain> [attacker_computer]
```

* Remove all machines from the configuration list in <target_computer>

```powershell
rbcd_manager.exe -remove <target_computer> <domain>
```


# 🛰️ Reflexive Execution in C2 Frameworks

The compiled binary of rbcd_manager can also be executed reflexively through C2 frameworks such as Cobalt Strike, Sliver, Mythic, or Brute Ratel using .NET in-memory execution techniques.

Examples:

Cobalt Strike/Sliver
```powershell
execute-assembly rbcd_manager.exe <args>
```

<img width="953" height="834" alt="Screenshot From 2025-12-03 12-33-18" src="https://github.com/user-attachments/assets/37b45f57-df73-4177-ae94-92ef2456ef34" />
<img width="1108" height="588" alt="Screenshot From 2025-12-03 12-31-44" src="https://github.com/user-attachments/assets/151534c8-955a-4f68-be0b-ecc037940be2" />


This allows red team operators to run the tool fully in-memory, without touching disk, ideal for secure or stealthy assessments (always with proper authorization).

# 📌 Features

* Reads and updates the RBCD security descriptor (msDS-AllowedToActOnBehalfOfOtherIdentity)
* Adds ACEs without overwriting existing ones
* SID-to-name resolution
* Paging support for large domains
* Detailed error messages

# 📂 Build Instructions

1. Clone repository:

```powershell
git clone https://github.com/DarksBlackSk/rbcd_manager.git
```

2. Open rbcd_manager.sln or rbcd_manager.csproj in Visual Studio
3. Build in Release mode

# ⚠️ Disclaimer

This tool is intended for:

* System administrators
* Blue teams
* Security auditors
* Authorized penetration testing

Unauthorized use in real environments may be illegal.











