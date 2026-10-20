// Policy Viewer
// Mostra nome e dettagli delle policy applicate al PC, divise in Utente, Macchina e Aggiornamenti.
// Fonti: Intune/MDM (PolicyManager), Criteri di gruppo (gpresult), chiavi di registro Policies, stato e cronologia Windows Update.
//
// Opzioni da riga di comando: --export <file.html> (report senza interfaccia), --screenshot <cartella> (test: salva ogni pagina in PNG ed esce)

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml;
using Microsoft.Win32;

[assembly: AssemblyTitle("Policy Viewer")]
[assembly: AssemblyProduct("Policy Viewer")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace PolicyViewer
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string export = null, screenshots = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--export" && i + 1 < args.Length) export = args[++i];
                else if (args[i] == "--screenshot" && i + 1 < args.Length) screenshots = args[++i];
            }

            if (export != null)
            {
                try
                {
                    var data = Collector.Collect(null);
                    Report.WriteHtml(data, Path.GetFullPath(export));
                    return 0;
                }
                catch (Exception ex)
                {
                    try { File.WriteAllText(Path.GetFullPath(export) + ".error.txt", ex.ToString()); } catch { }
                    return 1;
                }
            }

            var app = new Application();
            app.ShutdownMode = ShutdownMode.OnMainWindowClose;
            app.DispatcherUnhandledException += delegate (object s, DispatcherUnhandledExceptionEventArgs e)
            {
                MessageBox.Show(e.Exception.ToString(), "Policy Viewer - errore", MessageBoxButton.OK, MessageBoxImage.Error);
                e.Handled = true;
            };
            return app.Run(new MainWindow(screenshots));
        }
    }

    #region Modello dati

    public class PolicyItem
    {
        public string Scope { get; set; }        // Utente / Macchina
        public string Source { get; set; }       // descrizione completa dell'origine
        public string SourceShort { get; set; }  // testo del badge
        public string SourceKind { get; set; }   // MDM, GPO, REG, WU
        public string Area { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string Description { get; set; }
        public string Details { get; set; }
        public string Path { get; set; }
        public bool IsUpdate { get; set; }

        public string DescriptionText { get { return string.IsNullOrEmpty(Description) ? "—" : Description; } }

        string search;
        public string SearchText
        {
            get
            {
                if (search == null)
                    search = string.Join("\n", new[] { Name, Value, Area, Source, Description, Path }.Where(x => x != null)).ToLowerInvariant();
                return search;
            }
        }
    }

    public class InfoRow
    {
        public string Label { get; set; }
        public string Value { get; set; }
        public InfoRow(string label, string value) { Label = label; Value = string.IsNullOrEmpty(value) ? "—" : value; }
    }

    public class GpoInfo
    {
        public string Scope { get; set; }
        public string Name { get; set; }
        public string Link { get; set; }
        public bool Applied { get; set; }
    }

    public class HistoryItem
    {
        public DateTime Date { get; set; }
        public string DateText { get { return Date == DateTime.MinValue ? "" : Date.ToString("dd/MM/yyyy HH:mm"); } }
        public string Title { get; set; }
        public string Operation { get; set; }
        public string Result { get; set; }
        public string ResultKind { get; set; }   // OK, KO, WARN, INFO
        public string SearchText { get { return ((Title ?? "") + "\n" + Result + "\n" + Operation).ToLowerInvariant(); } }
    }

    public class Snapshot
    {
        public DateTime CollectedAt;
        public bool IsAdmin;
        public string ComputerName = Environment.MachineName;
        public string UserName, UserSid;
        public bool UserIsCurrent = true;
        public List<PolicyItem> Items = new List<PolicyItem>();
        public List<InfoRow> Device = new List<InfoRow>();
        public List<InfoRow> Management = new List<InfoRow>();
        public List<GpoInfo> Gpos = new List<GpoInfo>();
        public List<InfoRow> UpdateStatus = new List<InfoRow>();
        public List<HistoryItem> History = new List<HistoryItem>();
        public List<string> Warnings = new List<string>();
        public Dictionary<string, string> Providers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public IEnumerable<PolicyItem> UserItems { get { return Items.Where(i => i.Scope == "Utente" && !i.IsUpdate); } }
        public IEnumerable<PolicyItem> MachineItems { get { return Items.Where(i => i.Scope == "Macchina" && !i.IsUpdate); } }
        public IEnumerable<PolicyItem> UpdateItems { get { return Items.Where(i => i.IsUpdate); } }
    }

    #endregion

    #region Raccolta

    static class Collector
    {
        const string PmRoot = @"SOFTWARE\Microsoft\PolicyManager";
        const string IntuneLabel = "Intune (MDM)";
        const string WufbLabel = "WUfB Deployment Service";
        static readonly string[] PmSuffixes = { "_ProviderSet", "_WinningProvider", "_ADMXInstanceData", "_LastWrite" };

        public static Snapshot Collect(Action<string> progress)
        {
            var s = new Snapshot { CollectedAt = DateTime.Now, IsAdmin = IsAdmin() };
            Step(s, progress, "Identificazione dell'utente connesso", delegate { ResolveUser(s); });

            // gpresult e' la parte piu' lenta: parte subito in parallelo al resto
            XmlDocument gpComputer = null, gpUser = null;
            string gpComputerErr = null, gpUserErr = null;
            var gpTasks = new List<Task>();
            if (s.IsAdmin) gpTasks.Add(Task.Factory.StartNew(delegate
            {
                try { gpComputer = RunGpresult("computer", null, out gpComputerErr); } catch (Exception ex) { gpComputerErr = ex.Message; }
            }));
            else s.Warnings.Add("Esecuzione senza privilegi di amministratore: le impostazioni GPO del computer non sono disponibili.");
            string gpUserArg = s.UserIsCurrent ? null : s.UserName;
            gpTasks.Add(Task.Factory.StartNew(delegate
            {
                try { gpUser = RunGpresult("user", gpUserArg, out gpUserErr); } catch (Exception ex) { gpUserErr = ex.Message; }
            }));

            Step(s, progress, "Lettura informazioni del dispositivo", delegate { CollectDevice(s); });
            Step(s, progress, "Lettura delle registrazioni MDM", delegate { CollectEnrollments(s); });
            Step(s, progress, "Lettura policy Intune del dispositivo", delegate { CollectMdm(s, "device", "Device", "Macchina"); });
            Step(s, progress, "Lettura policy Intune dell'utente", delegate { CollectMdm(s, s.UserSid, s.UserSid, "Utente"); });
            Step(s, progress, "Lettura chiavi di registro Policies (macchina)", delegate
            {
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies", "", "Macchina");
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\WOW6432Node\Policies", "WOW6432Node\\", "Macchina");
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", "CurrentVersion\\Policies\\", "Macchina");
            });
            Step(s, progress, "Lettura chiavi di registro Policies (utente)", delegate
            {
                CollectRegistry(s, Registry.Users, "HKU\\" + s.UserSid, s.UserSid + @"\Software\Policies", "", "Utente");
                CollectRegistry(s, Registry.Users, "HKU\\" + s.UserSid, s.UserSid + @"\Software\Microsoft\Windows\CurrentVersion\Policies", "CurrentVersion\\Policies\\", "Utente");
            });
            Step(s, progress, "Lettura stato di Windows Update", delegate { CollectUpdateState(s); });
            Step(s, progress, "Lettura cronologia di Windows Update", delegate { CollectUpdateHistory(s); });
            Step(s, progress, "Riepilogo Windows Update", delegate { BuildUpdateStatus(s); });

            if (progress != null) progress("Attesa risultati Criteri di gruppo (gpresult)");
            Task.WaitAll(gpTasks.ToArray());
            Step(s, progress, "Analisi Criteri di gruppo", delegate
            {
                if (gpComputer != null) ParseGp(s, gpComputer, "ComputerResults", "Macchina");
                else if (s.IsAdmin) s.Warnings.Add("GPO computer non disponibili: " + gpComputerErr);
                if (gpUser != null) ParseGp(s, gpUser, "UserResults", "Utente");
                else s.Warnings.Add("GPO utente non disponibili: " + gpUserErr);
            });
            return s;
        }

        static void Step(Snapshot s, Action<string> progress, string text, Action action)
        {
            if (progress != null) progress(text + "…");
            try { action(); }
            catch (Exception ex) { s.Warnings.Add(text + ": " + ex.Message); }
        }

        static bool IsAdmin()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void ResolveUser(Snapshot s)
        {
            var cur = WindowsIdentity.GetCurrent();
            s.UserSid = cur.User.Value;
            s.UserName = cur.Name;
            // Se il tool e' stato avviato con credenziali diverse (es. admin), le policy utente sono quelle di chi e' connesso alla sessione
            int session = Process.GetCurrentProcess().SessionId;
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                if (p.SessionId != session) continue;
                try
                {
                    using (var mo = new ManagementObject("Win32_Process.Handle=\"" + p.Id + "\""))
                    {
                        var sidOut = mo.InvokeMethod("GetOwnerSid", null, null);
                        var ownOut = mo.InvokeMethod("GetOwner", null, null);
                        string sid = sidOut["Sid"] as string;
                        if (string.IsNullOrEmpty(sid)) continue;
                        s.UserSid = sid;
                        s.UserName = ownOut["Domain"] + "\\" + ownOut["User"];
                        break;
                    }
                }
                catch { }
            }
            s.UserIsCurrent = string.Equals(s.UserSid, cur.User.Value, StringComparison.OrdinalIgnoreCase);
            if (!s.UserIsCurrent)
                s.Warnings.Add("Tool avviato come " + cur.Name + ": le policy utente mostrate sono quelle dell'utente connesso " + s.UserName + ".");
        }

        #region Dispositivo e MDM

        static void CollectDevice(Snapshot s)
        {
            string caption = null, lastBoot = null, manufacturer = null, model = null, serial = null;
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT Caption,LastBootUpTime FROM Win32_OperatingSystem").Get())
            {
                caption = (o["Caption"] as string ?? "").Replace("Microsoft ", "");
                try { lastBoot = ManagementDateTimeConverter.ToDateTime((string)o["LastBootUpTime"]).ToString("dd/MM/yyyy HH:mm"); } catch { }
            }
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT Manufacturer,Model FROM Win32_ComputerSystem").Get())
            {
                manufacturer = o["Manufacturer"] as string;
                model = o["Model"] as string;
            }
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS").Get())
                serial = o["SerialNumber"] as string;

            var join = ParseDsregcmd();
            Func<string, string> yn = delegate (string k) { string v; return join.TryGetValue(k, out v) ? (v == "YES" ? "Sì" : "No") : "?"; };
            string tenant;
            join.TryGetValue("TenantName", out tenant);

            s.Device.Add(new InfoRow("Nome computer", s.ComputerName));
            s.Device.Add(new InfoRow("Utente connesso", s.UserName));
            s.Device.Add(new InfoRow("Sistema operativo", caption));
            s.Device.Add(new InfoRow("Versione", WindowsVersion()));
            s.Device.Add(new InfoRow("Produttore / modello", (manufacturer + " " + model).Trim()));
            s.Device.Add(new InfoRow("Numero di serie", serial));
            s.Device.Add(new InfoRow("Join", "Entra ID: " + yn("AzureAdJoined") + "  ·  Dominio AD: " + yn("DomainJoined") + "  ·  Registrato: " + yn("WorkplaceJoined")));
            s.Device.Add(new InfoRow("Tenant", tenant));
            s.Device.Add(new InfoRow("Ultimo avvio", lastBoot));
        }

        public static string WindowsVersion()
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (k == null) return null;
                return string.Format("{0} (build {1}.{2})", k.GetValue("DisplayVersion"), k.GetValue("CurrentBuild"), k.GetValue("UBR"));
            }
        }

        static Dictionary<string, string> ParseDsregcmd()
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string output = RunProcess("dsregcmd.exe", "/status", 30000);
            foreach (Match m in Regex.Matches(output ?? "", @"^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$", RegexOptions.Multiline))
                if (!result.ContainsKey(m.Groups[1].Value)) result[m.Groups[1].Value] = m.Groups[2].Value;
            return result;
        }

        static void CollectEnrollments(Snapshot s)
        {
            using (var root = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments"))
            {
                if (root == null) { s.Management.Add(new InfoRow("MDM", "Dispositivo non registrato in alcun MDM")); return; }
                foreach (string id in root.GetSubKeyNames())
                {
                    RegistryKey key = null;
                    try { key = root.OpenSubKey(id); } catch (System.Security.SecurityException) { } catch (UnauthorizedAccessException) { }
                    using (var k = key)
                    {
                        if (k == null) continue;
                        string provider = k.GetValue("ProviderID") as string;
                        object type = k.GetValue("EnrollmentType");
                        if (provider == "MS DM Server") s.Providers[id] = IntuneLabel;
                        else if (provider == null && type is int && (int)type == 32) s.Providers[id] = WufbLabel;
                        else if (provider != null) s.Providers[id] = provider;
                        else continue;

                        if (s.Providers[id] != IntuneLabel && s.Providers[id] != WufbLabel) continue;
                        string upn = k.GetValue("UPN") as string;
                        string sync = LastSync(id);
                        var parts = new List<string>();
                        if (!string.IsNullOrEmpty(upn)) parts.Add(upn);
                        if (sync != null) parts.Add("ultima sincronizzazione " + sync);
                        parts.Add("ID " + id);
                        s.Management.Add(new InfoRow(s.Providers[id], string.Join("\n", parts)));
                    }
                }
            }
            if (s.Management.Count == 0) s.Management.Add(new InfoRow("MDM", "Nessuna registrazione Intune trovata"));

            // Intune Management Extension (app Win32, script, remediation)
            // Per gli utenti standard la chiave IME non e' leggibile: si verifica la presenza del servizio
            bool ime = File.Exists(@"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe")
                || Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\IntuneManagementExtension") != null;
            string imeLog = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log";
            string val = ime ? "Installata" : "Non installata";
            try { if (File.Exists(imeLog)) val += "  ·  log aggiornato " + File.GetLastWriteTime(imeLog).ToString("dd/MM/yyyy HH:mm"); } catch { }
            s.Management.Add(new InfoRow("Intune Management Extension", val));
        }

        static string LastSync(string id)
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\" + id + @"\Protected\ConnInfo"))
            {
                string v = k == null ? null : k.GetValue("ServerLastSuccessTime") as string;
                DateTime d;
                if (v != null && DateTime.TryParseExact(v, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out d))
                    return d.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
                return null;
            }
        }

        static string ProviderLabel(Snapshot s, string id)
        {
            if (string.IsNullOrEmpty(id)) return "MDM";
            string label;
            return s.Providers.TryGetValue(id, out label) ? label : "Provider " + id;
        }

        static void CollectMdm(Snapshot s, string scopeKey, string providerScope, string scope)
        {
            using (var root = Registry.LocalMachine.OpenSubKey(PmRoot + @"\current\" + scopeKey))
            {
                if (root == null) return;
                foreach (string area in root.GetSubKeyNames())
                {
                    if (area.Equals("knobs", StringComparison.OrdinalIgnoreCase)) continue;
                    using (var ak = root.OpenSubKey(area))
                    {
                        if (ak == null) continue;
                        var bases = new List<string>();
                        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (string n in ak.GetValueNames())
                        {
                            string b = n;
                            foreach (string suf in PmSuffixes)
                                if (b.EndsWith(suf, StringComparison.OrdinalIgnoreCase)) { b = b.Substring(0, b.Length - suf.Length); break; }
                            if (seen.Add(b)) bases.Add(b);
                        }
                        foreach (string name in bases) AddMdmItem(s, ak, scopeKey, providerScope, scope, area, name);
                    }
                }
            }
        }

        static void AddMdmItem(Snapshot s, RegistryKey ak, string scopeKey, string providerScope, string scope, string area, string name)
        {
            string winner = ak.GetValue(name + "_WinningProvider") as string;
            object raw = ak.GetValue(name);
            // Solo "_LastWrite" senza valore ne' provider: residuo di una policy non piu' assegnata
            if (raw == null && winner == null && ak.GetValue(name + "_ProviderSet") == null) return;
            string path = @"HKLM\" + PmRoot + @"\current\" + scopeKey + "\\" + area;
            // I criteri ADMX (e alcuni CSP) salvano il valore solo sotto il provider che l'ha impostato
            if (raw == null && winner != null)
            {
                string pp = PmRoot + @"\providers\" + winner + @"\default\" + providerScope + "\\" + area;
                using (var pk = Registry.LocalMachine.OpenSubKey(pp))
                {
                    if (pk != null) { raw = pk.GetValue(name); if (raw != null) path = @"HKLM\" + pp; }
                }
            }

            string provider = ProviderLabel(s, winner);
            bool isAdmx = area.Contains("~Policy~") || area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase) || ak.GetValue(name + "_ADMXInstanceData") != null;
            string rawText = FormatValue(raw);
            var details = new StringBuilder();
            details.AppendLine("CSP: ./" + (scope == "Utente" ? "User" : "Device") + "/Vendor/MSFT/Policy/Config/" + area + "/" + name);
            details.AppendLine("Valore grezzo: " + (rawText ?? "(non leggibile)"));
            details.AppendLine("Provider vincente: " + (winner ?? "?") + " (" + provider + ")");
            if (isAdmx) details.AppendLine("Tipo: criterio ADMX gestito via MDM");
            using (var meta = Registry.LocalMachine.OpenSubKey(PmRoot + @"\default\" + area + "\\" + name))
            {
                if (meta != null)
                {
                    object low = meta.GetValue("lowrange"), high = meta.GetValue("highrange"), def = meta.GetValue("value");
                    if (low != null && high != null) details.AppendLine("Intervallo consentito: " + low + " – " + high);
                    if (def != null) details.AppendLine("Valore predefinito: " + FormatValue(def));
                    string gpKey = meta.GetValue("GPBlockingRegKeyPath") as string;
                    if (gpKey != null) details.AppendLine("Equivalente GPO: HKLM\\" + gpKey + "\\" + meta.GetValue("GPBlockingRegValueName"));
                }
            }

            bool isUpdate = area.Equals("Update", StringComparison.OrdinalIgnoreCase) || area.Equals("DeliveryOptimization", StringComparison.OrdinalIgnoreCase);
            string description = Descriptions.Get(name);

            s.Items.Add(new PolicyItem
            {
                Scope = scope,
                Source = provider,
                SourceShort = provider == IntuneLabel ? "Intune" : provider,
                SourceKind = provider == WufbLabel ? "WU" : "MDM",
                Area = (isUpdate ? "Intune · " : "") + PrettyArea(area),
                Name = name,
                Value = (isAdmx ? DecodeAdmx(raw as string) : Descriptions.Decode(name, raw)) ?? rawText ?? "(non leggibile)",
                Description = description,
                Details = details.ToString().TrimEnd(),
                Path = path + "\\" + name,
                IsUpdate = isUpdate,
            });
        }

        static readonly Dictionary<string, string> AppNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "microsoft_edge", "Microsoft Edge" }, { "OneDriveNGSC", "OneDrive" }, { "GoogleUpdate", "Google Update" },
            { "chrome", "Google Chrome" }, { "Firefox", "Firefox" }, { "office16", "Microsoft Office" }, { "word16", "Word" },
            { "excel16", "Excel" }, { "outlk16", "Outlook" }, { "ppt16", "PowerPoint" }, { "teams", "Teams" },
        };

        // "microsoft_edgev80diff~Policy~microsoft_edge~SmartScreen" -> "Microsoft Edge › SmartScreen"
        static string PrettyArea(string area)
        {
            if (area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase)) return area.Substring(5) + " (ADMX)";
            int idx = area.IndexOf("~Policy~", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return area;
            string app = Regex.Replace(area.Substring(0, idx), @"(v\d+)?diff$", "", RegexOptions.IgnoreCase);
            var cats = area.Substring(idx + 8).Split('~').Select(c => Regex.Replace(c, "^Cat_", "")).ToList();
            if (cats.Count > 0) cats.RemoveAt(0);
            string appName;
            if (!AppNames.TryGetValue(app, out appName)) appName = app;
            return cats.Count == 0 ? appName : appName + " › " + string.Join(" › ", cats);
        }

        // "<enabled/><data id="SSLVersionMin" value="tls1.2"/>" -> "Abilitato · SSLVersionMin = tls1.2"
        static string DecodeAdmx(string raw)
        {
            if (string.IsNullOrEmpty(raw) || !raw.TrimStart().StartsWith("<")) return null;
            var parts = new List<string>();
            if (raw.Contains("<enabled")) parts.Add("Abilitato");
            else if (raw.Contains("<disabled")) parts.Add("Disabilitato");
            foreach (Match m in Regex.Matches(raw, "<data\\s+id=\"([^\"]*)\"\\s+value=\"([^\"]*)\"", RegexOptions.IgnoreCase))
            {
                string v = WebUtility.HtmlDecode(m.Groups[2].Value).Replace("\uF000", "; ").Trim(' ', ';');
                parts.Add(m.Groups[1].Value + " = " + v);
            }
            return parts.Count == 0 ? raw : string.Join("  ·  ", parts);
        }

        #endregion

        #region Registro

        static void CollectRegistry(Snapshot s, RegistryKey hive, string hiveName, string subPath, string areaPrefix, string scope)
        {
            using (var k = hive.OpenSubKey(subPath))
            {
                if (k == null) return;
                string display = hiveName == "HKLM" ? @"HKLM\" + subPath : hiveName + subPath.Substring(subPath.IndexOf('\\'));
                WalkRegistry(s, k, display, areaPrefix, "", scope, 0);
            }
        }

        static void WalkRegistry(Snapshot s, RegistryKey key, string fullPath, string areaPrefix, string rel, string scope, int depth)
        {
            foreach (string vn in key.GetValueNames())
            {
                object raw = key.GetValue(vn, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                string kind = "";
                try { kind = key.GetValueKind(vn).ToString(); } catch { }
                bool isUpdate = fullPath.IndexOf(@"\WindowsUpdate", StringComparison.OrdinalIgnoreCase) >= 0 || fullPath.IndexOf(@"\DeliveryOptimization", StringComparison.OrdinalIgnoreCase) >= 0;
                string name = vn.Length == 0 ? "(Predefinito)" : vn;
                string area = areaPrefix + (rel.Length == 0 ? "(radice)" : rel);
                s.Items.Add(new PolicyItem
                {
                    Scope = scope,
                    Source = "Registro (valore effettivo; scritto da GPO, Intune o software)",
                    SourceShort = "Registro",
                    SourceKind = "REG",
                    Area = (isUpdate ? "Registro · " : "") + area,
                    Name = name,
                    Value = (isUpdate ? Descriptions.Decode(vn, raw) : null) ?? FormatValue(raw),
                    Description = isUpdate ? Descriptions.Get(vn) : null,
                    Details = "Chiave: " + fullPath + "\nValore: " + name + "\nTipo: REG_" + RegKindName(kind) + "\nDati: " + FormatValue(raw)
                        + "\n\nIl registro mostra il valore effettivo ma non chi l'ha scritto: confrontare con le schede Intune e GPO.",
                    Path = fullPath + "\\" + name,
                    IsUpdate = isUpdate,
                });
            }
            if (depth > 15) return;
            foreach (string sub in key.GetSubKeyNames())
            {
                try
                {
                    using (var c = key.OpenSubKey(sub))
                        if (c != null) WalkRegistry(s, c, fullPath + "\\" + sub, areaPrefix, rel.Length == 0 ? sub : rel + "\\" + sub, scope, depth + 1);
                }
                catch { }
            }
        }

        static string RegKindName(string kind)
        {
            switch (kind)
            {
                case "DWord": return "DWORD";
                case "QWord": return "QWORD";
                case "String": return "SZ";
                case "ExpandString": return "EXPAND_SZ";
                case "MultiString": return "MULTI_SZ";
                case "Binary": return "BINARY";
                default: return kind.ToUpperInvariant();
            }
        }

        public static string FormatValue(object raw)
        {
            if (raw == null) return null;
            if (raw is int) return ((int)raw).ToString() + ((int)raw > 9 || (int)raw < 0 ? string.Format(" (0x{0:X})", (int)raw) : "");
            if (raw is long) return ((long)raw).ToString();
            if (raw is string[]) return string.Join("; ", (string[])raw);
            if (raw is byte[])
            {
                var b = (byte[])raw;
                string hex = BitConverter.ToString(b.Take(48).ToArray()).Replace("-", " ");
                return b.Length > 48 ? hex + " … (" + b.Length + " byte)" : hex;
            }
            return raw.ToString();
        }

        #endregion

        #region Criteri di gruppo

        static XmlDocument RunGpresult(string scope, string user, out string error)
        {
            error = null;
            string file = Path.Combine(Path.GetTempPath(), "PolicyViewer_gp_" + scope + "_" + Guid.NewGuid().ToString("N") + ".xml");
            string args = "/scope " + scope + (user != null ? " /user \"" + user + "\"" : "") + " /x \"" + file + "\" /f";
            string output = RunProcess("gpresult.exe", args, 180000);
            try
            {
                if (!File.Exists(file))
                {
                    error = string.IsNullOrWhiteSpace(output) ? "gpresult non ha prodotto risultati" : Regex.Replace(output.Trim(), @"\s+", " ");
                    return null;
                }
                var doc = new XmlDocument();
                doc.Load(file);
                return doc;
            }
            catch (Exception ex) { error = ex.Message; return null; }
            finally { try { File.Delete(file); } catch { } }
        }

        static XmlNode ChildNode(XmlNode n, string localName)
        {
            if (n == null) return null;
            foreach (XmlNode c in n.ChildNodes)
                if (c.NodeType == XmlNodeType.Element && c.LocalName == localName) return c;
            return null;
        }

        static string Child(XmlNode n, string localName)
        {
            var c = ChildNode(n, localName);
            return c == null ? null : c.InnerText.Trim();
        }

        static IEnumerable<XmlNode> Children(XmlNode n, string localName)
        {
            foreach (XmlNode c in n.ChildNodes)
                if (c.NodeType == XmlNodeType.Element && (localName == null || c.LocalName == localName)) yield return c;
        }

        static void ParseGp(Snapshot s, XmlDocument doc, string resultsName, string scope)
        {
            XmlNode res = doc.SelectSingleNode("//*[local-name()='" + resultsName + "']");
            if (res == null) return;

            var gpoNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (XmlNode g in Children(res, "GPO"))
            {
                string name = Child(g, "Name");
                string id = Child(ChildNode(g, "Path"), "Identifier");
                if (id != null) gpoNames[id] = name;
                bool applied = Child(g, "IsValid") != "false" && Child(g, "FilterAllowed") != "false" && Child(g, "AccessDenied") != "true" && Child(g, "Enabled") != "false";
                var link = ChildNode(g, "Link");
                string som = link != null ? Child(link, "SOMPath") : null;
                string reason = applied ? "Applicato" : Child(g, "AccessDenied") == "true" ? "Accesso negato" : Child(g, "FilterAllowed") == "false" ? "Escluso da filtro WMI/sicurezza" : "Non applicato";
                if (s.Gpos.Any(x => x.Name == name && x.Scope == scope)) continue;
                s.Gpos.Add(new GpoInfo { Scope = scope, Name = name, Applied = applied, Link = reason + (som != null ? "  ·  " + som : "") });
            }

            foreach (XmlNode ed in Children(res, "ExtensionData"))
            {
                string extName = Child(ed, "Name");
                XmlNode ext = ChildNode(ed, "Extension");
                if (ext == null) continue;
                foreach (XmlNode c in Children(ext, null)) AddGpItem(s, c, extName, scope, gpoNames);
            }
        }

        static readonly HashSet<string> GpSkip = new HashSet<string> { "GPO", "Precedence", "Explain", "Supported", "Category", "Identifier", "Domain" };

        static void CollectLeaves(XmlNode n, string prefix, List<string> leaves)
        {
            foreach (XmlNode c in Children(n, null))
            {
                if (GpSkip.Contains(c.LocalName)) continue;
                if (Children(c, null).Any()) CollectLeaves(c, prefix + c.LocalName + "/", leaves);
                else leaves.Add(prefix + c.LocalName + " = " + c.InnerText.Trim());
            }
        }

        static void AddGpItem(Snapshot s, XmlNode c, string extName, string scope, Dictionary<string, string> gpoNames)
        {
            string gpoId = Child(ChildNode(c, "GPO"), "Identifier");
            string gpoName;
            if (gpoId == null || !gpoNames.TryGetValue(gpoId, out gpoName)) gpoName = gpoId ?? "GPO";

            string display = Child(ChildNode(c, "Display"), "Name");
            string name = !string.IsNullOrEmpty(display) ? display : Child(c, "Name");
            if (string.IsNullOrEmpty(name)) name = Child(c, "KeyName");
            if (string.IsNullOrEmpty(name))
            {
                string kp = Child(c, "KeyPath");
                string vn = Child(ChildNode(c, "Value"), "Name");
                if (kp != null) name = kp + (vn != null ? "\\" + vn : "");
            }
            if (string.IsNullOrEmpty(name)) name = Child(c, "SystemAccessPolicyName");
            if (string.IsNullOrEmpty(name)) name = c.LocalName;

            var leaves = new List<string>();
            CollectLeaves(c, "", leaves);
            string state = Child(c, "State");
            var extra = leaves.Where(l => !Regex.IsMatch(l, "^(Name|KeyName|KeyPath|State|Display/Name) = ")).ToList();
            string value;
            if (state != null)
            {
                value = state == "Enabled" ? "Abilitato" : state == "Disabled" ? "Disabilitato" : state == "NotConfigured" ? "Non configurato" : state;
                var opts = extra.Where(l => l.EndsWith("/Name = ") == false).Take(3).Select(l => Regex.Replace(l, "^.*?([^/]+/[^/]+ = )", "$1")).ToList();
                if (opts.Count > 0) value += "  ·  " + string.Join("  ·  ", opts);
            }
            else value = string.Join("  ·  ", extra.Take(3));
            if (string.IsNullOrEmpty(value)) value = "(configurato)";

            string category = Child(c, "Category");
            string all = name + " " + category + " " + string.Join(" ", leaves);
            bool isUpdate = all.IndexOf("Windows Update", StringComparison.OrdinalIgnoreCase) >= 0 || all.IndexOf("WindowsUpdate", StringComparison.OrdinalIgnoreCase) >= 0;
            string explain = Child(c, "Explain");
            if (explain != null && explain.Length > 2000) explain = explain.Substring(0, 2000) + "…";

            s.Items.Add(new PolicyItem
            {
                Scope = scope,
                Source = "GPO: " + gpoName,
                SourceShort = gpoName,
                SourceKind = "GPO",
                Area = (isUpdate ? "GPO · " : "") + (string.IsNullOrEmpty(category) ? extName : category),
                Name = name,
                Value = value,
                Description = explain ?? Descriptions.Get(name),
                Details = "Estensione: " + extName + "\nTipo elemento: " + c.LocalName + "\nOggetto Criteri di gruppo: " + gpoName + "\n\n" + string.Join("\n", leaves),
                Path = Child(c, "KeyPath") ?? Child(c, "KeyName") ?? (category != null ? category + "/" + name : extName),
                IsUpdate = isUpdate,
            });
        }

        #endregion

        #region Windows Update

        static readonly Dictionary<string, string> PolicyStateNames = new Dictionary<string, string>
        {
            { "BranchReadinessLevel", "Canale effettivo" },
            { "QualityUpdatesDeferralInDays", "Rinvio qualitativi effettivo" },
            { "FeatureUpdatesDeferralInDays", "Rinvio funzionalità effettivo" },
            { "IsWUfBConfigured", "Windows Update for Business configurato" },
        };

        static void CollectUpdateState(Snapshot s)
        {
            const string psPath = @"SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState";
            using (var k = Registry.LocalMachine.OpenSubKey(psPath))
            {
                if (k == null) return;
                foreach (string vn in k.GetValueNames())
                {
                    object raw = k.GetValue(vn);
                    s.Items.Add(new PolicyItem
                    {
                        Scope = "Macchina",
                        Source = "Windows Update (stato effettivo calcolato dal client)",
                        SourceShort = "Stato WU",
                        SourceKind = "WU",
                        Area = "Stato effettivo Windows Update",
                        Name = vn,
                        Value = Descriptions.Decode(vn, raw) ?? FormatValue(raw),
                        Description = Descriptions.Get(vn) ?? "Valore effettivo calcolato da Windows Update a partire da tutte le policy applicate (GPO e MDM).",
                        Details = "Chiave: HKLM\\" + psPath + "\nValore grezzo: " + FormatValue(raw),
                        Path = @"HKLM\" + psPath + "\\" + vn,
                        IsUpdate = true,
                    });
                }
            }
        }

        static void CollectUpdateHistory(Snapshot s)
        {
            dynamic session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session"));
            dynamic searcher = session.CreateUpdateSearcher();
            int total = searcher.GetTotalHistoryCount();
            if (total == 0) return;
            dynamic entries = searcher.QueryHistory(0, Math.Min(total, 300));
            foreach (dynamic e in entries)
            {
                string title = null;
                try { title = e.Title; } catch { }
                if (string.IsNullOrEmpty(title)) continue;
                int result = 0, op = 0;
                DateTime date = DateTime.MinValue;
                try { result = (int)e.ResultCode; } catch { }
                try { op = (int)e.Operation; } catch { }
                try { date = ((DateTime)e.Date).ToLocalTime(); } catch { }
                string res, kind;
                switch (result)
                {
                    case 2: res = "Riuscito"; kind = "OK"; break;
                    case 3: res = "Riuscito con errori"; kind = "WARN"; break;
                    case 4: res = "Non riuscito"; kind = "KO"; break;
                    case 5: res = "Annullato"; kind = "WARN"; break;
                    case 1: res = "In corso"; kind = "INFO"; break;
                    default: res = "Non avviato"; kind = "INFO"; break;
                }
                s.History.Add(new HistoryItem
                {
                    Date = date,
                    Title = title,
                    Operation = op == 2 ? "Disinstallazione" : op == 1 ? "Installazione" : "Altro",
                    Result = res,
                    ResultKind = kind,
                });
            }
            s.History = s.History.OrderByDescending(h => h.Date).ToList();
        }

        static void BuildUpdateStatus(Snapshot s)
        {
            var st = s.UpdateStatus;
            st.Add(new InfoRow("Versione Windows", WindowsVersion()));

            string channel = PolicyStateValue("BranchReadinessLevel");
            if (channel != null) st.Add(new InfoRow("Canale", channel == "CB" ? "General Availability Channel" : channel));

            string q = PolicyStateValue("QualityUpdatesDeferralInDays"), f = PolicyStateValue("FeatureUpdatesDeferralInDays");
            if (q != null || f != null) st.Add(new InfoRow("Rinvio qualitativi / funzionalità", (q ?? "?") + " gg / " + (f ?? "?") + " gg"));

            var mdmUpdate = s.Items.Where(i => i.SourceKind == "MDM" && i.IsUpdate).GroupBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
            string dq, df, grace;
            if (mdmUpdate.TryGetValue("ConfigureDeadlineForQualityUpdates", out dq) | mdmUpdate.TryGetValue("ConfigureDeadlineForFeatureUpdates", out df))
                st.Add(new InfoRow("Scadenza qualitativi / funzionalità", (dq ?? "—") + " / " + (df ?? "—") + (mdmUpdate.TryGetValue("ConfigureDeadlineGracePeriod", out grace) ? "  (tolleranza " + grace + ")" : "")));
            string ahs, ahe;
            if (mdmUpdate.TryGetValue("ActiveHoursStart", out ahs) && mdmUpdate.TryGetValue("ActiveHoursEnd", out ahe))
                st.Add(new InfoRow("Orario di attività", ahs + " – " + ahe));
            string pq, pf;
            mdmUpdate.TryGetValue("PauseQualityUpdates", out pq);
            mdmUpdate.TryGetValue("PauseFeatureUpdates", out pf);
            if (pq != null || pf != null) st.Add(new InfoRow("Sospensione qualitativi / funzionalità", (pq ?? "—") + " / " + (pf ?? "—")));

            string wsus = null;
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"))
            using (var au = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"))
            {
                if (k != null && au != null && Convert.ToInt32(au.GetValue("UseWUServer", 0)) == 1) wsus = k.GetValue("WUServer") as string;
            }
            string defaultService = null;
            try
            {
                dynamic sm = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.ServiceManager"));
                foreach (dynamic svc in sm.Services)
                    if ((bool)svc.IsDefaultAUService) defaultService = (string)svc.Name;
            }
            catch { }
            st.Add(new InfoRow("Sorgente aggiornamenti", wsus != null ? "WSUS: " + wsus : defaultService ?? "Windows Update"));

            try
            {
                dynamic au = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.AutoUpdate"));
                dynamic r = au.Results;
                try { st.Add(new InfoRow("Ultima ricerca riuscita", ((DateTime)r.LastSearchSuccessDate).ToLocalTime().ToString("dd/MM/yyyy HH:mm"))); } catch { }
                try { st.Add(new InfoRow("Ultima installazione riuscita", ((DateTime)r.LastInstallationSuccessDate).ToLocalTime().ToString("dd/MM/yyyy HH:mm"))); } catch { }
            }
            catch { }

            // Aggiornamento mensile del sistema operativo, es. "2026-10 Aggiornamento della sicurezza (KB5127648) (26300.9711)"
            var lastCu = s.History.FirstOrDefault(h => h.ResultKind == "OK" && h.Operation == "Installazione"
                && Regex.IsMatch(h.Title, @"^\d{4}-\d{2} .*(cumulativ|Cumulative|Aggiornamento della sicurezza|Security Update|Aggiornamento .*per Windows)", RegexOptions.IgnoreCase)
                && !Regex.IsMatch(h.Title, @"\.NET", RegexOptions.IgnoreCase));
            if (lastCu != null) st.Add(new InfoRow("Ultimo aggiornamento mensile", lastCu.Title + " · " + lastCu.Date.ToString("dd/MM/yyyy")));
            int failed = s.History.Count(h => h.ResultKind == "KO" && h.Date > DateTime.Now.AddDays(-30));
            st.Add(new InfoRow("Installazioni non riuscite (30 gg)", failed.ToString()));

            bool reboot = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") != null
                || Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") != null;
            st.Add(new InfoRow("Riavvio in sospeso", reboot ? "Sì" : "No"));
        }

        static string PolicyStateValue(string name)
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState"))
            {
                object v = k == null ? null : k.GetValue(name);
                return v == null ? null : v.ToString();
            }
        }

        #endregion

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern int GetOEMCP();

        static Encoding ConsoleEncoding()
        {
            // TextInfo.OEMCodePage non e' affidabile con impostazioni internazionali personalizzate: si usa quella del sistema
            try { return Encoding.GetEncoding(GetOEMCP()); } catch { return Encoding.Default; }
        }

        static string RunProcess(string file, string args, int timeoutMs)
        {
            var enc = ConsoleEncoding();
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = enc,
                StandardErrorEncoding = enc,
            };
            using (var p = Process.Start(psi))
            {
                var so = p.StandardOutput.ReadToEndAsync();
                var se = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } return "timeout"; }
                return so.Result + se.Result;
            }
        }
    }

    #endregion

    #region Descrizioni impostazioni Windows Update

    static class Descriptions
    {
        static readonly Dictionary<string, string> Text = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "AllowAutoUpdate", "Comportamento degli aggiornamenti automatici: download, installazione e gestione del riavvio." },
            { "AllowMUUpdateService", "Consente di ricevere da Windows Update anche gli aggiornamenti di altri prodotti Microsoft (es. Office)." },
            { "AllowUpdateService", "Consente al dispositivo di contattare il servizio Microsoft Update." },
            { "ExcludeWUDriversInQualityUpdate", "Esclude i driver dagli aggiornamenti qualitativi di Windows Update." },
            { "ExcludeWUDrivers", "Esclusione effettiva dei driver dagli aggiornamenti qualitativi." },
            { "ExcludeWUDriversInQualityUpdates", "Esclude i driver dagli aggiornamenti qualitativi di Windows Update." },
            { "DeferQualityUpdatesPeriodInDays", "Giorni di rinvio degli aggiornamenti qualitativi (cumulativi mensili) rispetto al rilascio." },
            { "DeferFeatureUpdatesPeriodInDays", "Giorni di rinvio degli aggiornamenti di funzionalità (nuova versione di Windows) rispetto al rilascio." },
            { "DeferQualityUpdates", "Indica se il rinvio degli aggiornamenti qualitativi è attivo." },
            { "DeferFeatureUpdates", "Indica se il rinvio degli aggiornamenti di funzionalità è attivo." },
            { "QualityUpdatesDeferralInDays", "Rinvio degli aggiornamenti qualitativi effettivamente applicato dal client (giorni)." },
            { "FeatureUpdatesDeferralInDays", "Rinvio degli aggiornamenti di funzionalità effettivamente applicato dal client (giorni)." },
            { "PauseQualityUpdates", "Sospensione temporanea degli aggiornamenti qualitativi." },
            { "PauseFeatureUpdates", "Sospensione temporanea degli aggiornamenti di funzionalità." },
            { "PauseQualityUpdatesStartTime", "Data di inizio della sospensione degli aggiornamenti qualitativi." },
            { "PauseFeatureUpdatesStartTime", "Data di inizio della sospensione degli aggiornamenti di funzionalità." },
            { "SetEDURestart", "Modalità di riavvio per dispositivi didattici: riavvio solo fuori dall'orario di attività e senza utenti connessi." },
            { "ActiveHoursStart", "Inizio dell'orario di attività: in questa fascia Windows non riavvia automaticamente il PC." },
            { "ActiveHoursEnd", "Fine dell'orario di attività." },
            { "ActiveHoursMaxRange", "Durata massima che l'utente può impostare per l'orario di attività." },
            { "ConfigureFeatureUpdateUninstallPeriod", "Giorni entro cui è possibile disinstallare un aggiornamento di funzionalità e tornare alla versione precedente." },
            { "SetDisablePauseUXAccess", "Se attivo, nasconde all'utente il comando \"Sospendi aggiornamenti\"." },
            { "SetDisableUXWUAccess", "Se attivo, impedisce all'utente di usare le funzioni di Windows Update (ricerca e download manuali)." },
            { "BranchReadinessLevel", "Canale di rilascio da cui il dispositivo riceve gli aggiornamenti di funzionalità." },
            { "ManagePreviewBuilds", "Gestione delle build preview (programma Windows Insider)." },
            { "ConfigureDeadlineForFeatureUpdates", "Giorni dopo i quali installazione e riavvio di un aggiornamento di funzionalità diventano obbligatori." },
            { "ConfigureDeadlineForQualityUpdates", "Giorni dopo i quali installazione e riavvio di un aggiornamento qualitativo diventano obbligatori." },
            { "ConfigureDeadlineGracePeriod", "Giorni di tolleranza dopo la scadenza prima del riavvio forzato (aggiornamenti qualitativi)." },
            { "ConfigureDeadlineGracePeriodForFeatureUpdates", "Giorni di tolleranza dopo la scadenza prima del riavvio forzato (aggiornamenti di funzionalità)." },
            { "ConfigureDeadlineNoAutoReboot", "Se attivo, il PC non si riavvia automaticamente prima della scadenza configurata." },
            { "ScheduleImminentRestartWarning", "Preavviso del riavvio imminente." },
            { "ScheduleRestartWarning", "Preavviso prima di un riavvio pianificato." },
            { "UpdateNotificationLevel", "Livello delle notifiche di Windows Update mostrate all'utente." },
            { "AllowRebootlessUpdates", "Consente gli aggiornamenti senza riavvio (hotpatch), dove supportati." },
            { "DriverUpdateEnrolled", "Dispositivo registrato nel servizio di deployment di Windows Update for Business (Intune/Autopatch) per i driver." },
            { "FeatureUpdateEnrolled", "Dispositivo registrato nel servizio di deployment di Windows Update for Business per gli aggiornamenti di funzionalità." },
            { "QualityUpdateEnrolled", "Dispositivo registrato nel servizio di deployment di Windows Update for Business per gli aggiornamenti qualitativi (es. rilasci accelerati)." },
            { "QuickMachineRecoveryEnrolled", "Registrazione al ripristino rapido della macchina (Quick Machine Recovery)." },
            { "TargetReleaseVersion", "Versione di Windows bersaglio: il PC resta su questa versione o vi passa." },
            { "TargetReleaseVersionInfo", "Versione di Windows bersaglio (es. 24H2)." },
            { "ProductVersion", "Prodotto bersaglio per gli aggiornamenti di funzionalità (es. Windows 11)." },
            { "WUServer", "Server WSUS da cui vengono scaricati gli aggiornamenti." },
            { "UpdateServiceUrl", "Server WSUS da cui vengono scaricati gli aggiornamenti." },
            { "WUStatusServer", "Server WSUS a cui vengono inviati i report." },
            { "UseWUServer", "Se 1, il PC usa il server WSUS indicato in WUServer." },
            { "NoAutoUpdate", "Se 1, gli aggiornamenti automatici sono disattivati." },
            { "AUOptions", "Modalità aggiornamenti automatici da GPO." },
            { "ScheduledInstallDay", "Giorno pianificato per l'installazione." },
            { "ScheduledInstallTime", "Ora pianificata per l'installazione." },
            { "DisableDualScan", "Impedisce la ricerca su Windows Update quando è configurato WSUS." },
            { "DoNotConnectToWindowsUpdateInternetLocations", "Impedisce la connessione ai server Internet di Windows Update." },
            { "SetPolicyDrivenUpdateSourceForFeatureUpdates", "Sorgente degli aggiornamenti di funzionalità (Windows Update o WSUS)." },
            { "SetPolicyDrivenUpdateSourceForQualityUpdates", "Sorgente degli aggiornamenti qualitativi (Windows Update o WSUS)." },
            { "SetPolicyDrivenUpdateSourceForDriverUpdates", "Sorgente degli aggiornamenti dei driver (Windows Update o WSUS)." },
            { "SetPolicyDrivenUpdateSourceForOtherUpdates", "Sorgente degli altri aggiornamenti (Windows Update o WSUS)." },
            { "IsWUfBConfigured", "Indica se Windows Update for Business risulta configurato." },
            { "IsWUfBDualScanActive", "Indica se è attiva la doppia scansione WSUS + Windows Update." },
            { "IsDeferralIsActive", "Indica se è attivo un rinvio degli aggiornamenti." },
            { "UseUpdateClassPolicySource", "Indica se le sorgenti sono definite per classe di aggiornamento." },
            { "PolicySources", "Origini delle policy di aggiornamento rilevate dal client (valore interno)." },
            { "AllowTemporaryEnterpriseFeatureControl", "Abilita le funzionalità introdotte con gli aggiornamenti mensili che altrimenti restano disattivate nei PC gestiti." },
            { "TemporaryEnterpriseFeatureControlState", "Stato del controllo delle funzionalità introdotte con gli aggiornamenti mensili." },
            { "AllowOptionalContent", "Gestione dei contenuti opzionali e delle funzionalità in rollout graduale." },
            { "DODownloadMode", "Modalità di Ottimizzazione recapito (condivisione peer-to-peer dei download)." },
            { "NoAutoRebootWithLoggedOnUsers", "Se 1, nessun riavvio automatico con utenti connessi." },
        };

        static readonly Dictionary<string, Dictionary<int, string>> Maps = new Dictionary<string, Dictionary<int, string>>(StringComparer.OrdinalIgnoreCase)
        {
            { "AllowAutoUpdate", new Dictionary<int, string> { { 0, "Notifica prima del download" }, { 1, "Installazione automatica, l'utente pianifica il riavvio" }, { 2, "Installazione e riavvio automatici" }, { 3, "Installazione e riavvio automatici all'orario pianificato" }, { 4, "Installazione e riavvio automatici senza controllo utente" }, { 5, "Aggiornamenti automatici disattivati" }, { 6, "Installazione automatica con pianificazione dell'utente" } } },
            { "AUOptions", new Dictionary<int, string> { { 2, "Notifica download e installazione" }, { 3, "Download automatico, notifica installazione" }, { 4, "Download automatico e installazione pianificata" }, { 5, "Scelta dell'amministratore locale" }, { 7, "Download automatico, notifica installazione e riavvio" } } },
            { "BranchReadinessLevel", new Dictionary<int, string> { { 2, "Windows Insider – Canary/Dev" }, { 4, "Windows Insider – Beta" }, { 8, "Windows Insider – Release Preview" }, { 16, "General Availability Channel" }, { 32, "Semi-Annual Channel (legacy)" } } },
            { "ManagePreviewBuilds", new Dictionary<int, string> { { 0, "Build preview disabilitate" }, { 1, "Disabilitate dalla prossima release pubblica" }, { 2, "Build preview abilitate" }, { 3, "Scelta lasciata all'utente" } } },
            { "UpdateNotificationLevel", new Dictionary<int, string> { { 0, "Notifiche predefinite" }, { 1, "Solo avvisi di riavvio" }, { 2, "Nessuna notifica, inclusi gli avvisi di riavvio" } } },
            { "ScheduledInstallDay", new Dictionary<int, string> { { 0, "Ogni giorno" }, { 1, "Domenica" }, { 2, "Lunedì" }, { 3, "Martedì" }, { 4, "Mercoledì" }, { 5, "Giovedì" }, { 6, "Venerdì" }, { 7, "Sabato" } } },
            { "DODownloadMode", new Dictionary<int, string> { { 0, "Solo HTTP" }, { 1, "Peer nella stessa LAN" }, { 2, "Peer nel gruppo" }, { 3, "Peer su Internet" }, { 99, "Semplice (senza peer)" }, { 100, "Bypass (BITS)" } } },
        };

        static readonly HashSet<string> Booleans = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AllowMUUpdateService", "AllowUpdateService", "ExcludeWUDriversInQualityUpdate", "ExcludeWUDriversInQualityUpdates", "ExcludeWUDrivers",
            "PauseQualityUpdates", "PauseFeatureUpdates", "SetEDURestart", "SetDisablePauseUXAccess", "SetDisableUXWUAccess",
            "ConfigureDeadlineNoAutoReboot", "AllowRebootlessUpdates", "DriverUpdateEnrolled", "FeatureUpdateEnrolled", "QualityUpdateEnrolled",
            "QuickMachineRecoveryEnrolled", "DisableDualScan", "NoAutoUpdate", "UseWUServer", "DeferQualityUpdates", "DeferFeatureUpdates",
            "IsWUfBConfigured", "IsWUfBDualScanActive", "IsDeferralIsActive", "UseUpdateClassPolicySource", "NoAutoRebootWithLoggedOnUsers",
            "AllowTemporaryEnterpriseFeatureControl", "TemporaryEnterpriseFeatureControlState", "DoNotConnectToWindowsUpdateInternetLocations",
        };

        public static string Get(string name)
        {
            string d;
            return name != null && Text.TryGetValue(name, out d) ? d : null;
        }

        // Traduce un valore numerico noto in testo leggibile; null se non c'e' una traduzione
        public static string Decode(string name, object raw)
        {
            if (raw == null || name == null) return null;
            int v;
            if (raw is int) v = (int)raw;
            else if (!(raw is string) || !int.TryParse((string)raw, out v)) return null;

            Dictionary<int, string> map;
            string text;
            if (Maps.TryGetValue(name, out map) && map.TryGetValue(v, out text)) return text + " (" + v + ")";
            if (Booleans.Contains(name)) return v == 0 ? "No (0)" : v == 1 ? "Sì (1)" : v.ToString();
            if (name.StartsWith("SetPolicyDrivenUpdateSourceFor", StringComparison.OrdinalIgnoreCase))
                return v == 0 ? "Windows Update (0)" : v == 1 ? "WSUS (1)" : "Non configurato";
            if (name.EndsWith("InDays", StringComparison.OrdinalIgnoreCase) || name.StartsWith("ConfigureDeadline", StringComparison.OrdinalIgnoreCase) || name == "ConfigureFeatureUpdateUninstallPeriod")
                return v + (v == 1 ? " giorno" : " giorni");
            if (name == "ActiveHoursStart" || name == "ActiveHoursEnd" || name == "ScheduledInstallTime") return v.ToString("00") + ":00";
            if (name == "ActiveHoursMaxRange") return v + " ore";
            if (name == "ScheduleImminentRestartWarning") return v + " minuti";
            if (name == "ScheduleRestartWarning") return v + " ore";
            return null;
        }
    }

    #endregion

    #region Report HTML

    static class Report
    {
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static void WriteHtml(Snapshot s, string path)
        {
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"it\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.Append("<title>Policy " + H(s.ComputerName) + "</title><style>");
            sb.Append(":root{--bg:#f4f6fa;--card:#fff;--line:#e5e9f0;--text:#0f172a;--muted:#64748b;--accent:#2563eb}");
            sb.Append("@media (prefers-color-scheme:dark){:root{--bg:#0f141d;--card:#171e2a;--line:#273142;--text:#e2e8f0;--muted:#94a3b8;--accent:#60a5fa}}");
            sb.Append("*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 'Segoe UI',system-ui,sans-serif}");
            sb.Append("header{padding:28px 32px 8px}h1{margin:0;font-size:26px;font-weight:600}header p{margin:4px 0 0;color:var(--muted)}");
            sb.Append("main{padding:16px 32px 40px;max-width:1400px}section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}");
            sb.Append("h2{font-size:16px;margin:0 0 12px}h3{font-size:13px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}");
            sb.Append("table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}");
            sb.Append("th{color:var(--muted);font-size:12px;font-weight:600}td.k{color:var(--muted);width:240px}.b{display:inline-block;padding:1px 9px;border-radius:10px;font-size:12px;font-weight:600;background:#e6eefd;color:#1d4ed8}");
            sb.Append(".GPO{background:#f3e8ff;color:#7e22ce}.REG{background:#eef1f5;color:#475569}.WU{background:#ddf5ef;color:#0f766e}.desc{color:var(--muted);font-size:12.5px}");
            sb.Append("#q{width:100%;max-width:420px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font:inherit;margin-bottom:6px}");
            sb.Append(".warn{background:#fff8eb;border-color:#f6d58e;color:#7c4a03}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:900px){.grid2{grid-template-columns:1fr}td.k{width:auto}}");
            sb.Append("</style></head><body><header><h1>Policy applicate · " + H(s.ComputerName) + "</h1><p>Utente " + H(s.UserName) + " · raccolta del " + s.CollectedAt.ToString("dd/MM/yyyy HH:mm") + (s.IsAdmin ? "" : " · eseguito senza privilegi di amministratore") + "</p></header><main>");
            sb.Append("<input id=\"q\" placeholder=\"Filtra le tabelle…\" oninput=\"f(this.value)\">");

            if (s.Warnings.Count > 0)
            {
                sb.Append("<section class=\"warn\"><h2>Avvisi</h2>");
                foreach (var w in s.Warnings) sb.Append("<div>" + H(w) + "</div>");
                sb.Append("</section>");
            }

            sb.Append("<div class=\"grid2\">");
            InfoSection(sb, "Dispositivo", s.Device);
            InfoSection(sb, "Gestione e sincronizzazione", s.Management);
            sb.Append("</div><div class=\"grid2\"><section><h2>Criteri di gruppo (GPO)</h2><table>");
            if (s.Gpos.Count == 0) sb.Append("<tr><td>Nessun oggetto Criteri di gruppo rilevato.</td></tr>");
            foreach (var g in s.Gpos) sb.Append("<tr><td class=\"k\">" + H(g.Scope) + "</td><td><b>" + H(g.Name) + "</b><div class=\"desc\">" + H(g.Link) + "</div></td></tr>");
            sb.Append("</table></section>");
            InfoSection(sb, "Windows Update in breve", s.UpdateStatus);
            sb.Append("</div>");

            PolicySection(sb, "Policy utente", s.UserItems);
            PolicySection(sb, "Policy macchina", s.MachineItems);
            PolicySection(sb, "Policy aggiornamenti", s.UpdateItems);

            sb.Append("<section><h2>Cronologia Windows Update</h2><table class=\"f\"><tr><th>Data</th><th>Aggiornamento</th><th>Operazione</th><th>Esito</th></tr>");
            foreach (var h in s.History)
                sb.Append("<tr><td>" + H(h.DateText) + "</td><td>" + H(h.Title) + "</td><td>" + H(h.Operation) + "</td><td>" + H(h.Result) + "</td></tr>");
            sb.Append("</table></section></main>");
            sb.Append("<script>function f(q){q=q.toLowerCase();document.querySelectorAll('table.f tr').forEach(function(r){if(r.querySelector('th'))return;r.style.display=r.textContent.toLowerCase().indexOf(q)<0?'none':''})}</script>");
            sb.Append("</body></html>");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        static void InfoSection(StringBuilder sb, string title, List<InfoRow> rows)
        {
            sb.Append("<section><h2>" + H(title) + "</h2><table>");
            foreach (var r in rows) sb.Append("<tr><td class=\"k\">" + H(r.Label) + "</td><td>" + H(r.Value).Replace("\n", "<br>") + "</td></tr>");
            sb.Append("</table></section>");
        }

        static void PolicySection(StringBuilder sb, string title, IEnumerable<PolicyItem> items)
        {
            var list = items.OrderBy(i => i.Area).ThenBy(i => i.Name).ToList();
            sb.Append("<section><h2>" + H(title) + " (" + list.Count + ")</h2>");
            foreach (var g in list.GroupBy(i => i.Area))
            {
                sb.Append("<h3>" + H(g.Key) + "</h3><table class=\"f\"><tr><th style=\"width:32%\">Nome</th><th style=\"width:38%\">Valore</th><th>Origine</th></tr>");
                foreach (var i in g)
                {
                    sb.Append("<tr><td><b>" + H(i.Name) + "</b>");
                    if (!string.IsNullOrEmpty(i.Description)) sb.Append("<div class=\"desc\">" + H(i.Description.Length > 300 ? i.Description.Substring(0, 300) + "…" : i.Description) + "</div>");
                    sb.Append("</td><td>" + H(i.Value) + "</td><td><span class=\"b " + i.SourceKind + "\">" + H(i.SourceShort) + "</span></td></tr>");
                }
                sb.Append("</table>");
            }
            sb.Append("</section>");
        }
    }

    #endregion

    #region Interfaccia

    class MainWindow : Window
    {
        readonly FrameworkElement root;
        readonly string screenshotDir;
        Snapshot data;
        string page = "summary";
        string kindFilter = "";
        ListCollectionView policyView, historyView;

        readonly DataGrid policyGrid, historyGrid;
        readonly TextBox searchBox;

        public MainWindow(string screenshotDir)
        {
            this.screenshotDir = screenshotDir;
            Title = "Policy Viewer";
            Width = 1360; Height = 860; MinWidth = 1080; MinHeight = 640;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            FontFamily = new FontFamily("Segoe UI");
            Background = new SolidColorBrush(Color.FromRgb(0xF4, 0xF6, 0xFA));

            var asm = Assembly.GetExecutingAssembly();
            using (var st = asm.GetManifestResourceStream("MainWindow.xaml")) root = (FrameworkElement)XamlReader.Load(st);
            using (var ic = asm.GetManifestResourceStream("app.ico"))
                if (ic != null) Icon = BitmapFrame.Create(ic, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            Content = root;

            policyGrid = F<DataGrid>("PolicyGrid");
            historyGrid = F<DataGrid>("HistoryGrid");
            searchBox = F<TextBox>("SearchBox");

            NavHook("NavSummary", "summary");
            NavHook("NavUser", "user");
            NavHook("NavMachine", "machine");
            NavHook("NavUpdates", "updates");
            NavHook("NavHistory", "history");
            CardHook("CardUser", "NavUser");
            CardHook("CardMachine", "NavMachine");
            CardHook("CardUpdates", "NavUpdates");
            CardHook("CardHistory", "NavHistory");
            foreach (var chip in F<Panel>("Chips").Children.OfType<RadioButton>())
            {
                var c = chip;
                c.Checked += delegate { kindFilter = (string)c.Tag; RefreshFilter(); };
            }
            searchBox.TextChanged += delegate { RefreshFilter(); };
            policyGrid.SelectionChanged += delegate { ShowDetail(policyGrid.SelectedItem as PolicyItem); };
            policyGrid.Sorting += OnPolicySorting;
            F<Button>("BtnRefresh").Click += delegate { Reload(); };
            F<Button>("BtnExport").Click += delegate { Export(); };
            F<Button>("BtnCopy").Click += delegate { CopyDetail(); };
            F<Button>("BtnElevate").Click += delegate { Elevate(); };
            PreviewKeyDown += delegate (object s, KeyEventArgs e)
            {
                if (e.Key == Key.F5) Reload();
                else if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control) { searchBox.Focus(); searchBox.SelectAll(); }
            };

            F<TextBlock>("SideComputer").Text = Environment.MachineName;
            ShowPage("summary");
            Loaded += delegate { Reload(); };
        }

        T F<T>(string name) where T : class { return root.FindName(name) as T; }

        void NavHook(string name, string key)
        {
            F<RadioButton>(name).Checked += delegate { ShowPage(key); };
        }

        void CardHook(string card, string nav)
        {
            F<Border>(card).MouseLeftButtonUp += delegate { F<RadioButton>(nav).IsChecked = true; };
        }

        void Reload()
        {
            var overlay = F<FrameworkElement>("Overlay");
            var overlayText = F<TextBlock>("OverlayText");
            overlay.Visibility = Visibility.Visible;
            F<Button>("BtnRefresh").IsEnabled = F<Button>("BtnExport").IsEnabled = false;
            Action<string> progress = delegate (string msg) { Dispatcher.BeginInvoke(new Action(delegate { overlayText.Text = msg; })); };
            Task.Factory.StartNew(() => Collector.Collect(progress)).ContinueWith(t =>
            {
                overlay.Visibility = Visibility.Collapsed;
                F<Button>("BtnRefresh").IsEnabled = F<Button>("BtnExport").IsEnabled = true;
                if (t.IsFaulted)
                {
                    MessageBox.Show(this, t.Exception.GetBaseException().Message, "Policy Viewer", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                Apply(t.Result);
                if (screenshotDir != null) Dispatcher.BeginInvoke(new Action(TakeScreenshots), DispatcherPriority.ApplicationIdle);
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        void Apply(Snapshot s)
        {
            data = s;
            int userMdm = s.UserItems.Count(i => i.SourceKind == "MDM"), userGpo = s.UserItems.Count(i => i.SourceKind == "GPO"), userReg = s.UserItems.Count(i => i.SourceKind == "REG");
            int machMdm = s.MachineItems.Count(i => i.SourceKind == "MDM"), machGpo = s.MachineItems.Count(i => i.SourceKind == "GPO"), machReg = s.MachineItems.Count(i => i.SourceKind == "REG");
            F<TextBlock>("StatUser").Text = s.UserItems.Count().ToString();
            F<TextBlock>("StatUserSub").Text = string.Format("Intune {0} · GPO {1} · Registro {2}", userMdm, userGpo, userReg);
            F<TextBlock>("StatMachine").Text = s.MachineItems.Count().ToString();
            F<TextBlock>("StatMachineSub").Text = string.Format("Intune {0} · GPO {1} · Registro {2}", machMdm, machGpo, machReg);
            F<TextBlock>("StatUpdates").Text = s.UpdateItems.Count().ToString();
            F<TextBlock>("StatUpdatesSub").Text = string.Format("Intune {0} · WUfB DS {1} · stato effettivo {2}",
                s.UpdateItems.Count(i => i.SourceKind == "MDM"), s.UpdateItems.Count(i => i.Source == "WUfB Deployment Service"), s.UpdateItems.Count(i => i.SourceShort == "Stato WU"));
            var installed = s.History.Where(h => h.ResultKind == "OK" && h.Operation == "Installazione").ToList();
            F<TextBlock>("StatHistory").Text = installed.Count.ToString();
            F<TextBlock>("StatHistorySub").Text = installed.Count > 0 ? "Ultimo: " + installed[0].Date.ToString("dd/MM/yyyy") : "Nessuna installazione registrata";

            F<ItemsControl>("DeviceList").ItemsSource = s.Device;
            F<ItemsControl>("MdmList").ItemsSource = s.Management;
            F<ItemsControl>("GpoList").ItemsSource = s.Gpos;
            F<FrameworkElement>("GpoEmpty").Visibility = s.Gpos.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            F<ItemsControl>("UpdateSummaryList").ItemsSource = s.UpdateStatus;
            F<ItemsControl>("UpdateCards").ItemsSource = s.UpdateStatus;
            F<ItemsControl>("WarningList").ItemsSource = s.Warnings;
            F<FrameworkElement>("WarningCard").Visibility = s.Warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("BtnElevate").Visibility = s.IsAdmin ? Visibility.Collapsed : Visibility.Visible;
            F<TextBlock>("SideFooter").Text = "Raccolta: " + s.CollectedAt.ToString("dd/MM/yyyy HH:mm") + "\nAmministratore: " + (s.IsAdmin ? "sì" : "no") + "\nUtente: " + s.UserName;

            historyView = new ListCollectionView(s.History);
            historyView.Filter = o => MatchesSearch(((HistoryItem)o).SearchText);
            historyGrid.ItemsSource = historyView;
            ShowPage(page);
        }

        static readonly Dictionary<string, string[]> PageText = new Dictionary<string, string[]>
        {
            { "summary", new[] { "Riepilogo", "Panoramica delle policy applicate a questo PC e del suo stato di gestione." } },
            { "user", new[] { "Policy utente", "Impostazioni applicate all'utente connesso da Intune, Criteri di gruppo e chiavi di registro Policies (HKCU)." } },
            { "machine", new[] { "Policy macchina", "Impostazioni applicate al dispositivo da Intune, Criteri di gruppo e chiavi di registro Policies (HKLM). Le policy di Windows Update sono nella sezione Aggiornamenti." } },
            { "updates", new[] { "Policy aggiornamenti", "Anelli di aggiornamento, rinvii, scadenze e stato effettivo di Windows Update." } },
            { "history", new[] { "Cronologia aggiornamenti", "Ultime installazioni registrate da Windows Update su questo PC." } },
        };

        void ShowPage(string key)
        {
            page = key;
            F<TextBlock>("PageTitle").Text = PageText[key][0];
            F<TextBlock>("PageSubtitle").Text = PageText[key][1];
            bool policies = key == "user" || key == "machine" || key == "updates";
            F<FrameworkElement>("PageSummary").Visibility = key == "summary" ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("PagePolicies").Visibility = policies ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("PageHistory").Visibility = key == "history" ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("Toolbar").Visibility = key == "summary" ? Visibility.Collapsed : Visibility.Visible;
            F<FrameworkElement>("Chips").Visibility = policies ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("UpdateCards").Visibility = key == "updates" ? Visibility.Visible : Visibility.Collapsed;
            if (data == null) return;

            if (policies)
            {
                var items = (key == "user" ? data.UserItems : key == "machine" ? data.MachineItems : data.UpdateItems)
                    .OrderBy(i => i.Area, StringComparer.CurrentCultureIgnoreCase).ThenBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
                UpdateChips(items);
                policyView = new ListCollectionView(items);
                policyView.GroupDescriptions.Add(new PropertyGroupDescription("Area"));
                policyView.Filter = o => (kindFilter.Length == 0 || ((PolicyItem)o).SourceKind == kindFilter) && MatchesSearch(((PolicyItem)o).SearchText);
                foreach (var col in policyGrid.Columns) col.SortDirection = null;
                policyGrid.ItemsSource = policyView;
                ShowDetail(null);
            }
            UpdateCount();
        }

        void UpdateChips(List<PolicyItem> items)
        {
            string[] kinds = { "", "MDM", "GPO", "REG", "WU" };
            string[] labels = { "Tutte", "Intune", "GPO", "Registro", "Windows Update" };
            var chips = F<Panel>("Chips").Children.OfType<RadioButton>().ToList();
            for (int i = 0; i < chips.Count; i++)
            {
                int n = kinds[i].Length == 0 ? items.Count : items.Count(x => x.SourceKind == kinds[i]);
                chips[i].Content = labels[i] + "  " + n;
                chips[i].Visibility = n == 0 && i > 0 ? Visibility.Collapsed : Visibility.Visible;
            }
            if (chips.Any(c => c.IsChecked == true && c.Visibility != Visibility.Visible)) chips[0].IsChecked = true;
        }

        bool MatchesSearch(string text)
        {
            string q = searchBox.Text.Trim().ToLowerInvariant();
            return q.Length == 0 || q.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).All(text.Contains);
        }

        void RefreshFilter()
        {
            if (page == "history") { if (historyView != null) historyView.Refresh(); }
            else if (policyView != null) policyView.Refresh();
            UpdateCount();
        }

        void UpdateCount()
        {
            var count = F<TextBlock>("CountText");
            if (data == null) { count.Text = ""; return; }
            if (page == "history" && historyView != null) count.Text = historyView.Count + " di " + data.History.Count + " voci";
            else if (policyView != null && page != "summary")
            {
                count.Text = policyView.Count + " di " + policyView.SourceCollection.Cast<object>().Count() + " impostazioni";
                F<FrameworkElement>("GridEmpty").Visibility = policyView.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        // Ordinamento per colonna mantenendo il raggruppamento per area
        void OnPolicySorting(object sender, DataGridSortingEventArgs e)
        {
            e.Handled = true;
            if (policyView == null) return;
            var dir = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending;
            foreach (var col in policyGrid.Columns) if (col != e.Column) col.SortDirection = null;
            e.Column.SortDirection = dir;
            using (policyView.DeferRefresh())
            {
                policyView.SortDescriptions.Clear();
                policyView.SortDescriptions.Add(new SortDescription("Area", ListSortDirection.Ascending));
                policyView.SortDescriptions.Add(new SortDescription(e.Column.SortMemberPath, dir));
            }
        }

        void ShowDetail(PolicyItem item)
        {
            var panel = F<FrameworkElement>("DetailPanel");
            panel.DataContext = item;
            panel.Visibility = item == null ? Visibility.Collapsed : Visibility.Visible;
            F<FrameworkElement>("DetailEmpty").Visibility = item == null ? Visibility.Visible : Visibility.Collapsed;
            if (item != null) ((ScrollViewer)panel).ScrollToTop();
        }

        void CopyDetail()
        {
            var i = policyGrid.SelectedItem as PolicyItem;
            if (i == null) return;
            string text = string.Format("Nome: {0}\r\nValore: {1}\r\nDescrizione: {2}\r\nArea: {3}\r\nOrigine: {4}\r\nPercorso: {5}\r\n\r\n{6}",
                i.Name, i.Value, i.DescriptionText, i.Area, i.Source, i.Path, (i.Details ?? "").Replace("\n", "\r\n"));
            try { Clipboard.SetText(text); } catch { }
        }

        void Export()
        {
            if (data == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Esporta report policy",
                Filter = "Report HTML (*.html)|*.html",
                FileName = "Policy_" + data.ComputerName + "_" + data.CollectedAt.ToString("yyyyMMdd_HHmm") + ".html",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                Report.WriteHtml(data, dlg.FileName);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Esportazione non riuscita", MessageBoxButton.OK, MessageBoxImage.Error); }
        }

        void Elevate()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location) { UseShellExecute = true, Verb = "runas" });
                Close();
            }
            catch (Win32Exception) { }
        }

        // Solo per test: salva una PNG per pagina e chiude
        void TakeScreenshots()
        {
            Directory.CreateDirectory(screenshotDir);
            var navs = new[] { "NavSummary", "NavUser", "NavMachine", "NavUpdates", "NavHistory" };
            foreach (string nav in navs)
            {
                F<RadioButton>(nav).IsChecked = true;
                if (page != "summary" && page != "history" && policyView != null && policyView.Count > 0)
                    policyGrid.SelectedItem = policyView.GetItemAt(Math.Min(1, policyView.Count - 1));
                root.UpdateLayout();
                Dispatcher.Invoke(new Action(delegate { }), DispatcherPriority.Background);
                var dpi = VisualTreeHelper.GetDpi(root);
                var bmp = new RenderTargetBitmap((int)(root.ActualWidth * dpi.DpiScaleX), (int)(root.ActualHeight * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
                bmp.Render(root);
                var enc = new PngBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create(bmp));
                using (var fs = File.Create(Path.Combine(screenshotDir, nav.Substring(3) + ".png"))) enc.Save(fs);
            }
            Close();
        }
    }

    #endregion
}
