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
rbcd_manager.exe FS-X1 ATTACK REDTOPS.COM
```

<img width="1023" height="325" alt="image" src="https://github.com/user-attachments/assets/48ded9c5-fa5b-457c-ad68-f583d9f9a2cd" />


## 2) Verification Mode

Scans all domain computers and displays which ones have non-default RBCD entries.

```powershell
rbcd_manager.exe -verify <domain>
```

Example:

```powershell
rbcd_manager.exe -verify REDTOPS.COM
```

<img width="1023" height="325" alt="image" src="https://github.com/user-attachments/assets/b4f7cb1c-f12a-4e0f-a5bc-3c08857d3cdd" />


## 3) List RBCD Configurations

```powershell
rbcd_manager.exe -list <domain>
```

Example:

```powershell
rbcd_manager.exe -list REDTOPS.COM
```

<img width="1023" height="283" alt="image" src="https://github.com/user-attachments/assets/036de7f3-2696-43ce-aea9-469be7441892" />



## 4) Create Computer Account

```powershell
rbcd_manager.exe -create <computer_name> <domain> [password]
```

Example:

```powershell
rbcd_manager.exe -create FAKE01 REDTOPS.COM dEKSIO#@MISPAss
```

<img width="1023" height="222" alt="image" src="https://github.com/user-attachments/assets/001144e6-1858-44c0-9699-3a0a3bd7ffa9" />

<img width="778" height="508" alt="image" src="https://github.com/user-attachments/assets/518f9315-f473-406e-ac19-28059218d6cb" />


* When a password is not specified, a random one will be generated and the user will be informed aboud it

```powershell
rbcd_manager.exe -create <computer_name> <domain>
```

Example:

```powershell
rbcd_manager.exe -create FAKE02 REDTOPS.COM
```

<img width="1002" height="276" alt="image" src="https://github.com/user-attachments/assets/e52165fb-7346-424b-841e-2764fbe695a1" />

<img width="767" height="535" alt="image" src="https://github.com/user-attachments/assets/ed88b405-66b9-46ec-b174-4ef0e78ec6f4" />


## 5) Remove RBCD Configuration 

* Remove a specific machine from the configuration list in <target_computer>

```powershell
rbcd_manager.exe -remove <target_computer> <domain> [attacker_computer]
```

Example: In this case, we have three machines configured (ATTACK, FAKE01, and FAKE02) in the list of the FS-X1 machine.

<img width="1441" height="285" alt="image" src="https://github.com/user-attachments/assets/ec42d7a0-1102-46f7-ad44-3a3a8cf953d7" />

>>> The goal is to remove only the configuration of the FAKE01 machine while leaving the other configurations unchanged.

```powershell
rbcd_manager.exe -remove FS-X1 REDTOPS.COM FAKE01
```
```powershell
rbcd_manager.exe -list REDTOPS.COM
```

<img width="1441" height="483" alt="image" src="https://github.com/user-attachments/assets/43c5da68-93e0-497a-9958-05fd43ce218e" />



* Remove all machines from the configuration list in <target_computer>

```powershell
rbcd_manager.exe -remove <target_computer> <domain>
```

Example: Just like before, we have the three machines FS-X1, FAKE01, and FAKE02 configured, but this time we are going to remove all configurations

<img width="1441" height="291" alt="image" src="https://github.com/user-attachments/assets/7a60c207-b606-4bbb-b0ff-5474b7dc3907" />

```powershell
rbcd_manager.exe -remove FS-X1 REDTOPS.COM
```
```powershell
rbcd_manager.exe -list REDTOPS.COM
```

<img width="1441" height="465" alt="image" src="https://github.com/user-attachments/assets/de712f2e-601a-4a06-9fe5-ce2ccd7fff4c" />



# 🛰️ Reflexive Execution in C2 Frameworks

The compiled binary of rbcd_manager can also be executed reflexively through C2 frameworks such as Cobalt Strike, Sliver, Mythic, or Brute Ratel using .NET in-memory execution techniques.

Examples:

Cobalt Strike
```powershell
execute-assembly rbcd_manager.exe <args>
```

<img width="953" height="834" alt="Screenshot From 2025-12-03 12-33-18" src="https://github.com/user-attachments/assets/37b45f57-df73-4177-ae94-92ef2456ef34" />
<img width="1108" height="588" alt="Screenshot From 2025-12-03 12-31-44" src="https://github.com/user-attachments/assets/151534c8-955a-4f68-be0b-ecc037940be2" />

Sliver
```bash
execute-assembly rbcd_manager.exe <args>
```

<img width="1977" height="964" alt="image" src="https://github.com/user-attachments/assets/346c1181-837e-4965-8f5a-444c27e7169b" />

<img width="1977" height="964" alt="image" src="https://github.com/user-attachments/assets/a62e6f89-9dea-4274-8879-92f1d5ed4d8c" />


- This allows red team operators to run the tool fully in-memory, without touching disk, ideal for secure or stealthy assessments (always with proper authorization).

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











