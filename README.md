# Intune Policy Viewer

Applicazione Windows (singolo `.exe`, nessuna installazione) che mostra **nome e dettagli delle policy applicate al PC**, divise per sezione:

| Sezione | Contenuto |
|---|---|
| **Utente** | Policy Intune/MDM dell'utente connesso, GPO utente, chiavi `HKCU\Software\Policies` |
| **Macchina** | Policy Intune/MDM del dispositivo (CSP e ADMX: Edge, OneDrive, BitLocker, Defender…), GPO computer, chiavi `HKLM\SOFTWARE\Policies` |
| **Sicurezza** | BitLocker, firewall (incluse le regole distribuite da Intune), LAPS, Device Guard/VBS, Secure Boot, TPM, UAC, opzioni di sicurezza, criteri account, controllo e diritti utente (`secedit`, da amministratore) |
| **Defender** | Policy Defender da Intune/GPO, configurazione effettiva dell'antivirus, regole ASR con nome, esclusioni, stato (tempo reale, manomissioni, firme, onboarding Defender for Endpoint) |
| **Aggiornamenti** | Anelli di aggiornamento (rinvii, scadenze, orario di attività, canale), Windows Update for Business Deployment Service, stato effettivo calcolato da Windows Update, policy WSUS/GPO |

In più: riepilogo del dispositivo (join Entra ID/AD, tenant, ultima sincronizzazione MDM), elenco GPO applicati/filtrati, **cronologia di Windows Update** ed **esportazione in report HTML**.

Per ogni impostazione il pannello di dettaglio mostra valore decodificato, descrizione (per le policy di Windows Update), area, origine (Intune, GPO, registro, Windows Update), percorso di registro/CSP, provider vincente, intervallo consentito e chiave GPO equivalente.

## Uso

Avviare `PolicyViewer.exe`.

- Funziona anche da **utente standard**. Da amministratore mostra anche i GPO del computer (`gpresult /scope computer`); il pulsante *Riavvia come amministratore* compare nel riepilogo quando serve.
- Se avviato con credenziali diverse (es. account admin), le policy utente mostrate sono quelle dell'**utente connesso alla sessione**.
- Ricerca: `Ctrl+F`; aggiornamento: `F5`. Filtri per origine nella barra sopra la tabella.

Riga di comando:

```
PolicyViewer.exe --export C:\Temp\report.html     # report HTML senza interfaccia (exit code 0 = ok)
PolicyViewer.exe --screenshot C:\Temp\shots       # test: salva una PNG per pagina ed esce
```

> Nota: i **nomi dei profili Intune** (es. "Win11 - Update Ring") non sono memorizzati sul dispositivo: per le policy MDM viene mostrato il nome dell'impostazione CSP/ADMX, raggruppato per area.

## Fonti dati (sola lettura)

- `HKLM\SOFTWARE\Microsoft\PolicyManager\current` e `...\providers` – policy MDM effettive e valori ADMX
- `HKLM\SOFTWARE\Microsoft\Enrollments`, `...\Provisioning\OMADM\Accounts` – registrazioni MDM e ultima sincronizzazione
- `gpresult /x` – GPO applicati e relative impostazioni
- `HKLM`/`HKU\<SID>` `...\Policies` – valori di policy effettivi nel registro
- `HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState` – stato effettivo di Windows Update
- API COM `Microsoft.Update.*` – cronologia, ultima ricerca/installazione, servizio predefinito
- `dsregcmd /status`, WMI – informazioni sul dispositivo

Il programma non modifica nulla e non invia dati in rete.

## Compilazione

Richiede solo Windows con .NET Framework 4.8 (incluso in Windows 10/11): usa il compilatore C# di sistema.

```powershell
.\src\build.ps1          # produce PolicyViewer.exe nella cartella principale
```

| File | Ruolo |
|---|---|
| `src/Program.cs` | raccolta dati, logica dell'interfaccia, export HTML |
| `src/MainWindow.xaml` | interfaccia WPF (incorporata nell'exe come risorsa) |
| `src/app.manifest` | `asInvoker`, DPI per monitor |
| `src/app.ico` | icona (rigenerata da `build.ps1` se assente) |
