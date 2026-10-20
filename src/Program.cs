// Policy Viewer
// Shows the name and details of the policies applied to the PC: user, machine, security, Defender and Windows Update.
// Sources: Intune/MDM (PolicyManager), Group Policy (gpresult), Policies registry keys, Windows Update state and history.
//
// Command line: --export <file.html> (report without UI), --screenshot <folder> (test: saves one PNG per page and exits),
// --anonymize (replaces PC name, user, email, serial number, tenant and IDs: for screenshots and reports to share)

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
[assembly: AssemblyVersion("1.1.0.0")]
[assembly: AssemblyFileVersion("1.1.0.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace PolicyViewer
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string export = null, screenshots = null;
            bool anonymize = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--export" && i + 1 < args.Length) export = args[++i];
                else if (args[i] == "--screenshot" && i + 1 < args.Length) screenshots = args[++i];
                else if (args[i] == "--anonymize") anonymize = true;
            }

            if (export != null)
            {
                try
                {
                    var data = Collector.Collect(null);
                    if (anonymize) Anonymizer.Apply(data);
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
                MessageBox.Show(e.Exception.ToString(), "Policy Viewer - error", MessageBoxButton.OK, MessageBoxImage.Error);
                e.Handled = true;
            };
            return app.Run(new MainWindow(screenshots, anonymize));
        }
    }

    static class Fmt
    {
        public const string DateTime = "yyyy-MM-dd HH:mm";
        public const string Date = "yyyy-MM-dd";
    }

    #region Data model

    public class PolicyItem
    {
        public string Scope { get; set; }        // User / Machine
        public string Source { get; set; }       // full description of the source
        public string SourceShort { get; set; }  // badge text
        public string SourceKind { get; set; }   // MDM, GPO, REG, WU, EFF
        public string Area { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string Description { get; set; }
        public string Details { get; set; }
        public string Path { get; set; }
        public bool IsUpdate { get; set; }
        public bool IsSecurity { get; set; }
        public bool IsDefender { get; set; }

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
        public string DateText { get { return Date == DateTime.MinValue ? "" : Date.ToString(Fmt.DateTime); } }
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
        public List<InfoRow> SecurityStatus = new List<InfoRow>();
        public List<InfoRow> DefenderStatus = new List<InfoRow>();
        public List<HistoryItem> History = new List<HistoryItem>();
        public List<string> Warnings = new List<string>();
        public Dictionary<string, string> Providers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public IEnumerable<PolicyItem> UserItems { get { return Items.Where(i => i.Scope == "User" && !i.IsUpdate && !i.IsSecurity); } }
        public IEnumerable<PolicyItem> MachineItems { get { return Items.Where(i => i.Scope == "Machine" && !i.IsUpdate && !i.IsSecurity); } }
        public IEnumerable<PolicyItem> SecurityItems { get { return Items.Where(i => i.IsSecurity && !i.IsDefender && !i.IsUpdate); } }
        public IEnumerable<PolicyItem> DefenderItems { get { return Items.Where(i => i.IsDefender && !i.IsUpdate); } }
        public IEnumerable<PolicyItem> UpdateItems { get { return Items.Where(i => i.IsUpdate); } }
    }

    #endregion

    #region Collection

    static class Collector
    {
        const string PmRoot = @"SOFTWARE\Microsoft\PolicyManager";
        const string IntuneLabel = "Intune (MDM)";
        const string WufbLabel = "WUfB Deployment Service";
        static readonly string[] PmSuffixes = { "_ProviderSet", "_WinningProvider", "_ADMXInstanceData", "_LastWrite" };

        public static Snapshot Collect(Action<string> progress)
        {
            var s = new Snapshot { CollectedAt = DateTime.Now, IsAdmin = IsAdmin() };
            Step(s, progress, "Identifying the signed-in user", delegate { ResolveUser(s); });

            // gpresult is the slowest part: start it right away, in parallel with the rest
            XmlDocument gpComputer = null, gpUser = null;
            string gpComputerErr = null, gpUserErr = null;
            var gpTasks = new List<Task>();
            if (s.IsAdmin) gpTasks.Add(Task.Factory.StartNew(delegate
            {
                try { gpComputer = RunGpresult("computer", null, out gpComputerErr); } catch (Exception ex) { gpComputerErr = ex.Message; }
            }));
            else s.Warnings.Add("Running without administrator rights: computer Group Policy settings are not available.");
            string gpUserArg = s.UserIsCurrent ? null : s.UserName;
            gpTasks.Add(Task.Factory.StartNew(delegate
            {
                try { gpUser = RunGpresult("user", gpUserArg, out gpUserErr); } catch (Exception ex) { gpUserErr = ex.Message; }
            }));

            Step(s, progress, "Reading device information", delegate { CollectDevice(s); });
            Step(s, progress, "Reading MDM enrollments", delegate { CollectEnrollments(s); });
            Step(s, progress, "Reading Intune device policies", delegate { CollectMdm(s, "device", "Device", "Machine"); });
            Step(s, progress, "Reading Intune user policies", delegate { CollectMdm(s, s.UserSid, s.UserSid, "User"); });
            Step(s, progress, "Reading Policies registry keys (machine)", delegate
            {
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies", "", "Machine");
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\WOW6432Node\Policies", "WOW6432Node\\", "Machine");
                CollectRegistry(s, Registry.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", "CurrentVersion\\Policies\\", "Machine");
            });
            Step(s, progress, "Reading Policies registry keys (user)", delegate
            {
                CollectRegistry(s, Registry.Users, "HKU\\" + s.UserSid, s.UserSid + @"\Software\Policies", "", "User");
                CollectRegistry(s, Registry.Users, "HKU\\" + s.UserSid, s.UserSid + @"\Software\Microsoft\Windows\CurrentVersion\Policies", "CurrentVersion\\Policies\\", "User");
            });
            Step(s, progress, "Reading Intune firewall rules", delegate { Security.CollectFirewallMdm(s); });
            Step(s, progress, "Reading the effective Microsoft Defender configuration", delegate { Security.CollectDefender(s); });
            if (s.IsAdmin) Step(s, progress, "Reading local security policy (secedit)", delegate { Security.CollectSecedit(s); });
            else s.Warnings.Add("Running without administrator rights: local security policy (account, audit, user rights) and BitLocker/TPM status are not available.");
            Step(s, progress, "Security status", delegate { Security.BuildStatus(s); });
            Step(s, progress, "Reading Windows Update state", delegate { CollectUpdateState(s); });
            Step(s, progress, "Reading Windows Update history", delegate { CollectUpdateHistory(s); });
            Step(s, progress, "Windows Update summary", delegate { BuildUpdateStatus(s); });

            if (progress != null) progress("Waiting for Group Policy results (gpresult)");
            Task.WaitAll(gpTasks.ToArray());
            Step(s, progress, "Analyzing Group Policy", delegate
            {
                if (gpComputer != null) ParseGp(s, gpComputer, "ComputerResults", "Machine");
                else if (s.IsAdmin) s.Warnings.Add("Computer Group Policy not available: " + gpComputerErr);
                if (gpUser != null) ParseGp(s, gpUser, "UserResults", "User");
                else s.Warnings.Add("User Group Policy not available: " + gpUserErr);
            });
            foreach (var i in s.Items) i.IsDefender = Security.IsDefender(i);
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
            // If the tool was started with different credentials (e.g. admin), the user policies are those of the user signed in to the session
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
                s.Warnings.Add("Tool started as " + cur.Name + ": the user policies shown are those of the signed-in user " + s.UserName + ".");
        }

        #region Device and MDM

        static void CollectDevice(Snapshot s)
        {
            string caption = null, lastBoot = null, manufacturer = null, model = null, serial = null;
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT Caption,LastBootUpTime FROM Win32_OperatingSystem").Get())
            {
                caption = (o["Caption"] as string ?? "").Replace("Microsoft ", "");
                try { lastBoot = ManagementDateTimeConverter.ToDateTime((string)o["LastBootUpTime"]).ToString(Fmt.DateTime); } catch { }
            }
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT Manufacturer,Model FROM Win32_ComputerSystem").Get())
            {
                manufacturer = o["Manufacturer"] as string;
                model = o["Model"] as string;
            }
            foreach (ManagementObject o in new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS").Get())
                serial = o["SerialNumber"] as string;

            var join = ParseDsregcmd();
            Func<string, string> yn = delegate (string k) { string v; return join.TryGetValue(k, out v) ? (v == "YES" ? "Yes" : "No") : "?"; };
            string tenant;
            join.TryGetValue("TenantName", out tenant);

            s.Device.Add(new InfoRow("Computer name", s.ComputerName));
            s.Device.Add(new InfoRow("Signed-in user", s.UserName));
            s.Device.Add(new InfoRow("Operating system", caption));
            s.Device.Add(new InfoRow("Version", WindowsVersion()));
            s.Device.Add(new InfoRow("Manufacturer / model", (manufacturer + " " + model).Trim()));
            s.Device.Add(new InfoRow("Serial number", serial));
            s.Device.Add(new InfoRow("Join", "Entra ID: " + yn("AzureAdJoined") + "  ·  AD domain: " + yn("DomainJoined") + "  ·  Registered: " + yn("WorkplaceJoined")));
            s.Device.Add(new InfoRow("Tenant", tenant));
            s.Device.Add(new InfoRow("Last boot", lastBoot));
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
                if (root == null) { s.Management.Add(new InfoRow("MDM", "Device not enrolled in any MDM")); return; }
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
                        if (sync != null) parts.Add("last sync " + sync);
                        parts.Add("ID " + id);
                        s.Management.Add(new InfoRow(s.Providers[id], string.Join("\n", parts)));
                    }
                }
            }
            if (s.Management.Count == 0) s.Management.Add(new InfoRow("MDM", "No Intune enrollment found"));

            // Intune Management Extension (Win32 apps, scripts, remediations)
            // Standard users cannot read the IME key: check for the service instead
            bool ime = File.Exists(@"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe")
                || Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\IntuneManagementExtension") != null;
            string imeLog = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log";
            string val = ime ? "Installed" : "Not installed";
            try { if (File.Exists(imeLog)) val += "  ·  log updated " + File.GetLastWriteTime(imeLog).ToString(Fmt.DateTime); } catch { }
            s.Management.Add(new InfoRow("Intune Management Extension", val));
        }

        static string LastSync(string id)
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\" + id + @"\Protected\ConnInfo"))
            {
                string v = k == null ? null : k.GetValue("ServerLastSuccessTime") as string;
                DateTime d;
                if (v != null && DateTime.TryParseExact(v, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out d))
                    return d.ToLocalTime().ToString(Fmt.DateTime);
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
            // Only "_LastWrite" with neither value nor provider: leftover of a policy that is no longer assigned
            if (raw == null && winner == null && ak.GetValue(name + "_ProviderSet") == null) return;
            string path = @"HKLM\" + PmRoot + @"\current\" + scopeKey + "\\" + area;
            // ADMX policies (and some CSPs) store the value only under the provider that set it
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
            details.AppendLine("CSP: ./" + (scope == "User" ? "User" : "Device") + "/Vendor/MSFT/Policy/Config/" + area + "/" + name);
            details.AppendLine("Raw value: " + (rawText ?? "(not readable)"));
            details.AppendLine("Winning provider: " + (winner ?? "?") + " (" + provider + ")");
            if (isAdmx) details.AppendLine("Type: ADMX policy managed via MDM");
            using (var meta = Registry.LocalMachine.OpenSubKey(PmRoot + @"\default\" + area + "\\" + name))
            {
                if (meta != null)
                {
                    object low = meta.GetValue("lowrange"), high = meta.GetValue("highrange"), def = meta.GetValue("value");
                    if (low != null && high != null) details.AppendLine("Allowed range: " + low + " – " + high);
                    if (def != null) details.AppendLine("Default value: " + FormatValue(def));
                    string gpKey = meta.GetValue("GPBlockingRegKeyPath") as string;
                    if (gpKey != null) details.AppendLine("Equivalent GPO: HKLM\\" + gpKey + "\\" + meta.GetValue("GPBlockingRegValueName"));
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
                Value = (isAdmx ? DecodeAdmx(raw as string) : Descriptions.Decode(name, raw)) ?? rawText ?? "(not readable)",
                Description = description,
                Details = details.ToString().TrimEnd(),
                Path = path + "\\" + name,
                IsUpdate = isUpdate,
                IsSecurity = Security.IsSecurityArea(area),
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

        // "<enabled/><data id="SSLVersionMin" value="tls1.2"/>" -> "Enabled · SSLVersionMin = tls1.2"
        static string DecodeAdmx(string raw)
        {
            if (string.IsNullOrEmpty(raw) || !raw.TrimStart().StartsWith("<")) return null;
            var parts = new List<string>();
            if (raw.Contains("<enabled")) parts.Add("Enabled");
            else if (raw.Contains("<disabled")) parts.Add("Disabled");
            foreach (Match m in Regex.Matches(raw, "<data\\s+id=\"([^\"]*)\"\\s+value=\"([^\"]*)\"", RegexOptions.IgnoreCase))
            {
                string v = WebUtility.HtmlDecode(m.Groups[2].Value).Replace("\uF000", "; ").Trim(' ', ';');
                parts.Add(m.Groups[1].Value + " = " + v);
            }
            return parts.Count == 0 ? raw : string.Join("  ·  ", parts);
        }

        #endregion

        #region Registry

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
                string name = vn.Length == 0 ? "(Default)" : vn;
                string area = areaPrefix + (rel.Length == 0 ? "(root)" : rel);
                s.Items.Add(new PolicyItem
                {
                    Scope = scope,
                    Source = "Registry (effective value; written by GPO, Intune or software)",
                    SourceShort = "Registry",
                    SourceKind = "REG",
                    Area = (isUpdate ? "Registry · " : "") + area,
                    Name = name,
                    Value = (isUpdate ? Descriptions.Decode(vn, raw) : null) ?? FormatValue(raw),
                    Description = isUpdate ? Descriptions.Get(vn) : null,
                    Details = "Key: " + fullPath + "\nValue: " + name + "\nType: REG_" + RegKindName(kind) + "\nData: " + FormatValue(raw)
                        + "\n\nThe registry shows the effective value but not who wrote it: compare with the Intune and GPO entries.",
                    Path = fullPath + "\\" + name,
                    IsUpdate = isUpdate,
                    IsSecurity = Security.IsSecurityPath(fullPath),
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
                return b.Length > 48 ? hex + " … (" + b.Length + " bytes)" : hex;
            }
            return raw.ToString();
        }

        #endregion

        #region Group Policy

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
                    error = string.IsNullOrWhiteSpace(output) ? "gpresult produced no results" : Regex.Replace(output.Trim(), @"\s+", " ");
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
                string reason = applied ? "Applied" : Child(g, "AccessDenied") == "true" ? "Access denied" : Child(g, "FilterAllowed") == "false" ? "Excluded by WMI/security filter" : "Not applied";
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
                value = state == "NotConfigured" ? "Not configured" : state;
                var opts = extra.Where(l => l.EndsWith("/Name = ") == false).Take(3).Select(l => Regex.Replace(l, "^.*?([^/]+/[^/]+ = )", "$1")).ToList();
                if (opts.Count > 0) value += "  ·  " + string.Join("  ·  ", opts);
            }
            else value = string.Join("  ·  ", extra.Take(3));
            if (string.IsNullOrEmpty(value)) value = "(configured)";

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
                Details = "Extension: " + extName + "\nElement type: " + c.LocalName + "\nGroup Policy Object: " + gpoName + "\n\n" + string.Join("\n", leaves),
                Path = Child(c, "KeyPath") ?? Child(c, "KeyName") ?? (category != null ? category + "/" + name : extName),
                IsUpdate = isUpdate,
                IsSecurity = Security.IsSecurityGp(extName, category, Child(c, "KeyPath") ?? Child(c, "KeyName")),
            });
        }

        #endregion

        #region Windows Update

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
                        Scope = "Machine",
                        Source = "Windows Update (effective state computed by the client)",
                        SourceShort = "WU state",
                        SourceKind = "WU",
                        Area = "Windows Update effective state",
                        Name = vn,
                        Value = Descriptions.Decode(vn, raw) ?? FormatValue(raw),
                        Description = Descriptions.Get(vn) ?? "Effective value computed by Windows Update from all applied policies (GPO and MDM).",
                        Details = "Key: HKLM\\" + psPath + "\nRaw value: " + FormatValue(raw),
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
                    case 2: res = "Succeeded"; kind = "OK"; break;
                    case 3: res = "Succeeded with errors"; kind = "WARN"; break;
                    case 4: res = "Failed"; kind = "KO"; break;
                    case 5: res = "Aborted"; kind = "WARN"; break;
                    case 1: res = "In progress"; kind = "INFO"; break;
                    default: res = "Not started"; kind = "INFO"; break;
                }
                s.History.Add(new HistoryItem
                {
                    Date = date,
                    Title = title,
                    Operation = op == 2 ? "Uninstall" : op == 1 ? "Install" : "Other",
                    Result = res,
                    ResultKind = kind,
                });
            }
            s.History = s.History.OrderByDescending(h => h.Date).ToList();
        }

        static void BuildUpdateStatus(Snapshot s)
        {
            var st = s.UpdateStatus;
            st.Add(new InfoRow("Windows version", WindowsVersion()));

            string channel = PolicyStateValue("BranchReadinessLevel");
            if (channel != null) st.Add(new InfoRow("Channel", channel == "CB" ? "General Availability Channel" : channel));

            string q = PolicyStateValue("QualityUpdatesDeferralInDays"), f = PolicyStateValue("FeatureUpdatesDeferralInDays");
            if (q != null || f != null) st.Add(new InfoRow("Quality / feature deferral", (q ?? "?") + " d / " + (f ?? "?") + " d"));

            var mdmUpdate = s.Items.Where(i => i.SourceKind == "MDM" && i.IsUpdate).GroupBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
            string dq, df, grace;
            if (mdmUpdate.TryGetValue("ConfigureDeadlineForQualityUpdates", out dq) | mdmUpdate.TryGetValue("ConfigureDeadlineForFeatureUpdates", out df))
                st.Add(new InfoRow("Quality / feature deadline", (dq ?? "—") + " / " + (df ?? "—") + (mdmUpdate.TryGetValue("ConfigureDeadlineGracePeriod", out grace) ? "  (grace period " + grace + ")" : "")));
            string ahs, ahe;
            if (mdmUpdate.TryGetValue("ActiveHoursStart", out ahs) && mdmUpdate.TryGetValue("ActiveHoursEnd", out ahe))
                st.Add(new InfoRow("Active hours", ahs + " – " + ahe));
            string pq, pf;
            mdmUpdate.TryGetValue("PauseQualityUpdates", out pq);
            mdmUpdate.TryGetValue("PauseFeatureUpdates", out pf);
            if (pq != null || pf != null) st.Add(new InfoRow("Quality / feature pause", (pq ?? "—") + " / " + (pf ?? "—")));

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
            st.Add(new InfoRow("Update source", wsus != null ? "WSUS: " + wsus : defaultService ?? "Windows Update"));

            try
            {
                dynamic au = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.AutoUpdate"));
                dynamic r = au.Results;
                try { st.Add(new InfoRow("Last successful scan", ((DateTime)r.LastSearchSuccessDate).ToLocalTime().ToString(Fmt.DateTime))); } catch { }
                try { st.Add(new InfoRow("Last successful install", ((DateTime)r.LastInstallationSuccessDate).ToLocalTime().ToString(Fmt.DateTime))); } catch { }
            }
            catch { }

            // Monthly OS update; titles follow the OS language, e.g. "2026-10 Security Update (KB5127648) (26300.9711)"
            // or "2026-10 Aggiornamento della sicurezza (KB5127648) (26300.9711)"
            var lastCu = s.History.FirstOrDefault(h => h.ResultKind == "OK" && h.Operation == "Install"
                && Regex.IsMatch(h.Title, @"^\d{4}-\d{2} .*(cumulativ|Cumulative|Aggiornamento della sicurezza|Security Update|Aggiornamento .*per Windows|Update for Windows)", RegexOptions.IgnoreCase)
                && !Regex.IsMatch(h.Title, @"\.NET", RegexOptions.IgnoreCase));
            if (lastCu != null) st.Add(new InfoRow("Last monthly update", lastCu.Title + " · " + lastCu.Date.ToString(Fmt.Date)));
            int failed = s.History.Count(h => h.ResultKind == "KO" && h.Date > DateTime.Now.AddDays(-30));
            st.Add(new InfoRow("Failed installs (30 days)", failed.ToString()));

            bool reboot = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") != null
                || Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") != null;
            st.Add(new InfoRow("Pending restart", reboot ? "Yes" : "No"));
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
            // TextInfo.OEMCodePage is unreliable with customized regional settings: use the system one
            try { return Encoding.GetEncoding(GetOEMCP()); } catch { return Encoding.Default; }
        }

        public static string RunProcess(string file, string args, int timeoutMs)
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

    #region Security

    static class Security
    {
        const string IntuneLabel = "Intune (MDM)";
        public const string AsrArea = "Attack surface reduction (ASR)";
        public const string ExclusionsArea = "Microsoft Defender · exclusions";

        static readonly HashSet<string> Areas = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Defender", "BitLocker", "DeviceGuard", "DmaGuard", "LocalPoliciesSecurityOptions", "LocalUsersAndGroups", "Security", "SecureBoot",
            "WindowsDefenderSecurityCenter", "DeviceLock", "DeviceInstallation", "DataProtection", "Firewall", "LAPS", "SmartScreen",
            "WindowsDefenderApplicationGuard", "ApplicationControl", "AppLocker", "Authentication", "CredentialProviders", "CredentialsUI",
            "CredentialsDelegation", "Cryptography", "VirtualizationBasedTechnology", "UserRights", "Audit", "ExploitGuard", "Kerberos",
            "LocalSecurityAuthority", "WindowsLogon", "MSSecurityGuide", "MSSLegacy", "PassportForWork", "TenantRestrictions",
            "EnhancedStorage", "AttackSurfaceReduction", "WindowsSandbox",
        };

        public static bool IsSecurityArea(string area)
        {
            string a = area.StartsWith("ADMX_", StringComparison.OrdinalIgnoreCase) ? area.Substring(5) : area;
            return Areas.Contains(a);
        }

        static readonly Regex SecurityPath = new Regex(
            @"\\(Windows Defender|Microsoft Defender|Windows Defender Security Center|Windows Advanced Threat Protection|FVE|WindowsFirewall|PassportForWork|DeviceGuard|LAPS|SmartScreen|Biometrics|AdmPwd)(\\|$)|CurrentVersion\\Policies\\System$",
            RegexOptions.IgnoreCase);

        public static bool IsSecurityPath(string path) { return SecurityPath.IsMatch(path); }

        static readonly Regex DefenderText = new Regex(@"Defender|AttackSurfaceReduction|ExploitGuard|Advanced Threat Protection", RegexOptions.IgnoreCase);

        // Defender page: antivirus/EDR settings (configured by Intune or GPO, and effective values); the firewall stays under Security
        public static bool IsDefender(PolicyItem i)
        {
            if (!i.IsSecurity) return false;
            if (i.SourceKind == "EFF") return i.SourceShort == "Defender";
            string text = i.Area + " " + i.Path;
            return DefenderText.IsMatch(text) && text.IndexOf("Firewall", StringComparison.OrdinalIgnoreCase) < 0;
        }

        // gpresult categories follow the OS language: match both English and Italian terms
        static readonly Regex SecurityCategory = new Regex(@"Defender|BitLocker|Firewall|SmartScreen|Credential|Sicurezza|Security|LAPS|Device Guard|Exploit", RegexOptions.IgnoreCase);

        public static bool IsSecurityGp(string extName, string category, string key)
        {
            if (extName != null && Regex.IsMatch(extName, "^(Security|Windows Firewall|Public Key|Software Restriction|Advanced Audit Configuration|AppLocker)", RegexOptions.IgnoreCase)) return true;
            if (category != null && SecurityCategory.IsMatch(category)) return true;
            return key != null && IsSecurityPath(key);
        }

        #region Helpers

        static List<ManagementBaseObject> Wmi(string ns, string query)
        {
            var list = new List<ManagementBaseObject>();
            try
            {
                using (var srch = new ManagementObjectSearcher(ns, query))
                    foreach (ManagementBaseObject o in srch.Get()) list.Add(o);
            }
            catch { }
            return list;
        }

        static object P(ManagementBaseObject o, string name)
        {
            try { return o[name]; } catch { return null; }
        }

        static bool B(object v) { return v is bool && (bool)v; }

        static string CimDate(object v)
        {
            try { return ManagementDateTimeConverter.ToDateTime((string)v).ToString(Fmt.DateTime); } catch { return null; }
        }

        static void AddEff(Snapshot s, string sourceShort, string source, string area, string name, string value, string description, string details, string path)
        {
            s.Items.Add(new PolicyItem
            {
                Scope = "Machine",
                Source = source,
                SourceShort = sourceShort,
                SourceKind = "EFF",
                Area = area,
                Name = name,
                Value = string.IsNullOrEmpty(value) ? "(empty)" : value,
                Description = description,
                Details = details,
                Path = path,
                IsSecurity = true,
            });
        }

        #endregion

        #region Intune firewall

        public static void CollectFirewallMdm(Snapshot s)
        {
            const string root = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm";
            using (var k = Registry.LocalMachine.OpenSubKey(root))
            {
                if (k == null) return;
                AddFirewallValues(s, k, root, "");
                foreach (string sub in k.GetSubKeyNames())
                    using (var c = k.OpenSubKey(sub))
                        if (c != null) AddFirewallValues(s, c, root + "\\" + sub, sub);
            }
        }

        static void AddFirewallValues(Snapshot s, RegistryKey k, string path, string sub)
        {
            foreach (string vn in k.GetValueNames())
            {
                object raw = k.GetValue(vn);
                string text = raw as string;
                string name = vn, value = Collector.FormatValue(raw), details = "Key: HKLM\\" + path + "\nValue: " + vn;
                if (text != null && text.StartsWith("v2.", StringComparison.OrdinalIgnoreCase))
                {
                    // Rule format: v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=443|App=...|Name=...|
                    var f = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string part in text.Split('|'))
                    {
                        int eq = part.IndexOf('=');
                        if (eq <= 0) continue;
                        string key = part.Substring(0, eq), val = part.Substring(eq + 1);
                        f[key] = f.ContainsKey(key) ? f[key] + ", " + val : val;
                    }
                    string v;
                    if (f.TryGetValue("Name", out v)) name = v;
                    var parts = new List<string>();
                    if (f.TryGetValue("Action", out v)) parts.Add(v);
                    if (f.TryGetValue("Dir", out v)) parts.Add(v == "In" ? "Inbound" : v == "Out" ? "Outbound" : v);
                    if (f.TryGetValue("Protocol", out v)) parts.Add(v == "6" ? "TCP" : v == "17" ? "UDP" : v == "1" ? "ICMP" : "protocol " + v);
                    if (f.TryGetValue("LPort", out v)) parts.Add("local port " + v);
                    if (f.TryGetValue("RPort", out v)) parts.Add("remote port " + v);
                    if (f.TryGetValue("App", out v)) parts.Add(System.IO.Path.GetFileName(v));
                    if (f.TryGetValue("Active", out v) && v.Equals("FALSE", StringComparison.OrdinalIgnoreCase)) parts.Add("inactive");
                    value = string.Join("  ·  ", parts);
                    details += "\nRule ID: " + vn + "\n\n" + string.Join("\n", f.Select(x => x.Key + " = " + x.Value));
                }
                s.Items.Add(new PolicyItem
                {
                    Scope = "Machine",
                    Source = IntuneLabel,
                    SourceShort = "Intune",
                    SourceKind = "MDM",
                    Area = "Firewall" + (sub.Length > 0 ? " · " + sub : ""),
                    Name = name,
                    Value = value,
                    Description = sub == "FirewallRules" ? "Windows Firewall rule deployed by Intune (Firewall CSP)." : null,
                    Details = details,
                    Path = "HKLM\\" + path + "\\" + vn,
                    IsSecurity = true,
                });
            }
        }

        #endregion

        #region Microsoft Defender

        class DefPref
        {
            public string Name, Description;
            public Dictionary<int, string> Map;
            public DefPref(string name, string description, Dictionary<int, string> map) { Name = name; Description = description; Map = map; }
        }

        static readonly Dictionary<int, string> OffOnAudit = new Dictionary<int, string> { { 0, "Off" }, { 1, "On (block)" }, { 2, "Audit only" } };

        static readonly DefPref[] DefenderPrefs =
        {
            new DefPref("DisableRealtimeMonitoring", "If Yes, real-time protection is turned off.", null),
            new DefPref("DisableBehaviorMonitoring", "If Yes, behavior monitoring is turned off.", null),
            new DefPref("DisableIOAVProtection", "If Yes, downloaded files and attachments are not scanned.", null),
            new DefPref("DisableScriptScanning", "If Yes, scripts are not scanned.", null),
            new DefPref("DisableArchiveScanning", "If Yes, archives (zip, cab…) are not scanned.", null),
            new DefPref("DisableEmailScanning", "If Yes, email messages are not scanned.", null),
            new DefPref("DisableRemovableDriveScanning", "If Yes, removable drives are not scanned during a full scan.", null),
            new DefPref("PUAProtection", "Protection against potentially unwanted applications (PUA).", OffOnAudit),
            new DefPref("EnableNetworkProtection", "Network protection: blocks connections to malicious domains and IPs.", OffOnAudit),
            new DefPref("EnableControlledFolderAccess", "Controlled folder access (ransomware protection).",
                new Dictionary<int, string> { { 0, "Off" }, { 1, "On (block)" }, { 2, "Audit only" }, { 3, "Block disk modification only" }, { 4, "Audit disk modification only" } }),
            new DefPref("MAPSReporting", "Microsoft MAPS membership (cloud-delivered protection).",
                new Dictionary<int, string> { { 0, "Off" }, { 1, "Basic" }, { 2, "Advanced" } }),
            new DefPref("SubmitSamplesConsent", "Automatic sample submission to Microsoft.",
                new Dictionary<int, string> { { 0, "Always prompt" }, { 1, "Send safe samples automatically" }, { 2, "Never send" }, { 3, "Send all samples automatically" } }),
            new DefPref("CloudBlockLevel", "Cloud-delivered protection blocking level.",
                new Dictionary<int, string> { { 0, "Default" }, { 1, "Moderate" }, { 2, "High" }, { 4, "High+" }, { 6, "Zero tolerance" } }),
            new DefPref("CloudExtendedTimeout", "Extra seconds to wait for the cloud check before allowing a file.", null),
            new DefPref("SignatureUpdateInterval", "Signature update check interval (hours; 0 = default).", null),
            new DefPref("ScanScheduleDay", "Day of the scheduled scan.",
                new Dictionary<int, string> { { 0, "Every day" }, { 1, "Sunday" }, { 2, "Monday" }, { 3, "Tuesday" }, { 4, "Wednesday" }, { 5, "Thursday" }, { 6, "Friday" }, { 7, "Saturday" }, { 8, "Never" } }),
            new DefPref("ScanParameters", "Scheduled scan type.", new Dictionary<int, string> { { 1, "Quick scan" }, { 2, "Full scan" } }),
            new DefPref("EnableFileHashComputation", "File hash computation for indicators of compromise.", null),
        };

        static readonly Dictionary<string, string> AsrNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers" },
            { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes" },
            { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes" },
            { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" },
            { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
            { "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" },
            { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts" },
            { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
            { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes" },
            { "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes" },
            { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription" },
            { "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands" },
            { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB" },
            { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
            { "c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware" },
            { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode" },
            { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools" },
            { "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers" },
        };

        static readonly Dictionary<int, string> AsrActions = new Dictionary<int, string>
        {
            { 0, "Off" }, { 1, "Block" }, { 2, "Audit" }, { 5, "Not configured" }, { 6, "Warn" },
        };

        const string DefenderSource = "Microsoft Defender (effective configuration)";

        public static void CollectDefender(Snapshot s)
        {
            var pref = Wmi(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference").FirstOrDefault();
            if (pref == null) return;
            const string path = @"root\Microsoft\Windows\Defender : MSFT_MpPreference";

            foreach (var d in DefenderPrefs)
            {
                object v = P(pref, d.Name);
                if (v == null) continue;
                string text;
                if (v is bool) text = (bool)v ? "Yes" : "No";
                else
                {
                    int n = Convert.ToInt32(v);
                    string mapped;
                    text = d.Map != null && d.Map.TryGetValue(n, out mapped) ? mapped + " (" + n + ")" : n.ToString();
                }
                AddEff(s, "Defender", DefenderSource, "Microsoft Defender · effective configuration", d.Name, text, d.Description,
                    "Effective value read from Defender (result of Intune, GPO and local settings).\nMSFT_MpPreference." + d.Name + " = " + v, path + "." + d.Name);
            }

            var ids = P(pref, "AttackSurfaceReductionRules_Ids") as string[];
            var acts = P(pref, "AttackSurfaceReductionRules_Actions") as Array;
            if (ids != null)
            {
                for (int i = 0; i < ids.Length; i++)
                {
                    int act = acts != null && i < acts.Length ? Convert.ToInt32(acts.GetValue(i)) : -1;
                    string actText;
                    if (!AsrActions.TryGetValue(act, out actText)) actText = act.ToString();
                    string name;
                    if (!AsrNames.TryGetValue(ids[i], out name)) name = ids[i];
                    AddEff(s, "Defender", DefenderSource, AsrArea, name, actText + " (" + act + ")",
                        "Microsoft Defender attack surface reduction rule.",
                        "Rule GUID: " + ids[i] + "\nAction: " + act + " (0 off, 1 block, 2 audit, 6 warn)", path + ".AttackSurfaceReductionRules_Ids");
                }
            }

            foreach (string ex in new[] { "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "AttackSurfaceReductionOnlyExclusions", "ControlledFolderAccessAllowedApplications" })
            {
                var list = P(pref, ex) as string[];
                if (list == null || list.Length == 0) continue;
                AddEff(s, "Defender", DefenderSource, ExclusionsArea, ex, string.Join("; ", list),
                    "Items excluded from scanning or allowed. For standard users Defender does not reveal the content.", string.Join("\n", list), path + "." + ex);
            }
        }

        #endregion

        #region Local security policy

        static readonly Dictionary<string, string> SecNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "MinimumPasswordAge", "Minimum password age (days)" },
            { "MaximumPasswordAge", "Maximum password age (days)" },
            { "MinimumPasswordLength", "Minimum password length" },
            { "PasswordComplexity", "Password must meet complexity requirements" },
            { "PasswordHistorySize", "Enforce password history (passwords remembered)" },
            { "LockoutBadCount", "Account lockout threshold (invalid attempts)" },
            { "ResetLockoutCount", "Reset account lockout counter after (minutes)" },
            { "LockoutDuration", "Account lockout duration (minutes)" },
            { "AllowAdministratorLockout", "Allow Administrator account lockout" },
            { "RequireLogonToChangePassword", "Require logon to change password" },
            { "ForceLogoffWhenHourExpire", "Force logoff when logon hours expire" },
            { "NewAdministratorName", "Rename administrator account" },
            { "NewGuestName", "Rename guest account" },
            { "ClearTextPassword", "Store passwords using reversible encryption" },
            { "LSAAnonymousNameLookup", "Allow anonymous SID/Name translation" },
            { "EnableAdminAccount", "Administrator account status" },
            { "EnableGuestAccount", "Guest account status" },
            { "AuditSystemEvents", "Audit system events" },
            { "AuditLogonEvents", "Audit logon events" },
            { "AuditObjectAccess", "Audit object access" },
            { "AuditPrivilegeUse", "Audit privilege use" },
            { "AuditPolicyChange", "Audit policy change" },
            { "AuditAccountManage", "Audit account management" },
            { "AuditProcessTracking", "Audit process tracking" },
            { "AuditDSAccess", "Audit directory service access" },
            { "AuditAccountLogon", "Audit account logon events" },
            { "SeNetworkLogonRight", "Access this computer from the network" },
            { "SeInteractiveLogonRight", "Allow log on locally" },
            { "SeRemoteInteractiveLogonRight", "Allow log on through Remote Desktop Services" },
            { "SeDenyNetworkLogonRight", "Deny access to this computer from the network" },
            { "SeDenyInteractiveLogonRight", "Deny log on locally" },
            { "SeDenyRemoteInteractiveLogonRight", "Deny log on through Remote Desktop Services" },
            { "SeDenyBatchLogonRight", "Deny log on as a batch job" },
            { "SeDenyServiceLogonRight", "Deny log on as a service" },
            { "SeBatchLogonRight", "Log on as a batch job" },
            { "SeServiceLogonRight", "Log on as a service" },
            { "SeBackupPrivilege", "Back up files and directories" },
            { "SeRestorePrivilege", "Restore files and directories" },
            { "SeDebugPrivilege", "Debug programs" },
            { "SeShutdownPrivilege", "Shut down the system" },
            { "SeRemoteShutdownPrivilege", "Force shutdown from a remote system" },
            { "SeTakeOwnershipPrivilege", "Take ownership of files or other objects" },
            { "SeLoadDriverPrivilege", "Load and unload device drivers" },
            { "SeSecurityPrivilege", "Manage auditing and security log" },
            { "SeSystemtimePrivilege", "Change the system time" },
            { "SeTimeZonePrivilege", "Change the time zone" },
            { "SeImpersonatePrivilege", "Impersonate a client after authentication" },
            { "SeChangeNotifyPrivilege", "Bypass traverse checking" },
            { "SeCreateSymbolicLinkPrivilege", "Create symbolic links" },
            { "SeManageVolumePrivilege", "Perform volume maintenance tasks" },
            { "SeTcbPrivilege", "Act as part of the operating system" },
            { "SeSystemEnvironmentPrivilege", "Modify firmware environment values" },
            { "SeUndockPrivilege", "Remove computer from docking station" },
            { "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process" },
            { "SeAssignPrimaryTokenPrivilege", "Replace a process level token" },
            { "SeCreateGlobalPrivilege", "Create global objects" },
            { "SeProfileSingleProcessPrivilege", "Profile single process" },
            { "SeSystemProfilePrivilege", "Profile system performance" },
            { "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority" },
            { "SeCreatePagefilePrivilege", "Create a pagefile" },
            { "SeIncreaseWorkingSetPrivilege", "Increase a process working set" },
            { "SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session" },
        };

        static readonly Dictionary<string, string> SecSections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "System Access", "Account Policies" },
            { "Event Audit", "Audit Policy" },
            { "Privilege Rights", "User Rights Assignment" },
            { "Registry Values", "Security Options" },
        };

        public static void CollectSecedit(Snapshot s)
        {
            string file = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "PolicyViewer_sec_" + Guid.NewGuid().ToString("N") + ".inf");
            try
            {
                string output = Collector.RunProcess("secedit.exe", "/export /cfg \"" + file + "\" /areas SECURITYPOLICY USER_RIGHTS /quiet", 60000);
                if (!File.Exists(file)) throw new Exception(string.IsNullOrWhiteSpace(output) ? "secedit produced no results" : output.Trim());
                string section = null;
                foreach (string line in File.ReadAllLines(file))
                {
                    string l = line.Trim();
                    if (l.StartsWith("[")) { section = l.Trim('[', ']'); continue; }
                    string label;
                    if (section == null || !SecSections.TryGetValue(section, out label)) continue;
                    int eq = l.IndexOf('=');
                    if (eq <= 0) continue;
                    string key = l.Substring(0, eq).Trim(), raw = l.Substring(eq + 1).Trim();
                    AddSecedit(s, section, label, key, raw);
                }
            }
            finally { try { File.Delete(file); } catch { } }
        }

        static void AddSecedit(Snapshot s, string section, string label, string key, string raw)
        {
            string name, value = raw.Trim('"');
            if (section == "Registry Values")
            {
                // MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5  (type,value)
                name = key.Substring(key.LastIndexOf('\\') + 1);
                int comma = raw.IndexOf(',');
                if (comma > 0) value = raw.Substring(comma + 1).Trim('"').Replace("\",\"", "; ");
            }
            else if (section == "Privilege Rights")
            {
                name = SecNames.ContainsKey(key) ? SecNames[key] : key;
                value = string.Join("; ", raw.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(ResolveSid));
            }
            else
            {
                name = SecNames.ContainsKey(key) ? SecNames[key] : key;
                if (section == "Event Audit")
                {
                    switch (raw)
                    {
                        case "0": value = "No auditing (0)"; break;
                        case "1": value = "Success (1)"; break;
                        case "2": value = "Failure (2)"; break;
                        case "3": value = "Success and failure (3)"; break;
                    }
                }
                else if (key == "PasswordComplexity" || key == "ClearTextPassword" || key == "EnableAdminAccount" || key == "EnableGuestAccount"
                    || key == "RequireLogonToChangePassword" || key == "ForceLogoffWhenHourExpire" || key == "LSAAnonymousNameLookup" || key == "AllowAdministratorLockout")
                    value = raw == "1" ? "Yes (1)" : raw == "0" ? "No (0)" : raw;
            }
            AddEff(s, "Local policy", "Local security policy (effective, from secedit)", "Local policy · " + label, name, value,
                section == "Registry Values" ? "Security option: " + key : null,
                "secedit section: [" + section + "]\nKey: " + key + "\nRaw value: " + raw
                    + "\n\nEffective value of the local security policy (result of Intune, GPO and local configuration).",
                "secedit [" + section + "] " + key);
        }

        static string ResolveSid(string entry)
        {
            string sid = entry.Trim().TrimStart('*');
            if (!sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return sid;
            try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; } catch { return sid; }
        }

        #endregion

        #region Status

        public static void BuildStatus(Snapshot s)
        {
            var st = s.SecurityStatus;
            var ds = s.DefenderStatus;

            var mp = Wmi(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus").FirstOrDefault();
            if (mp != null)
            {
                string mode = P(mp, "AMRunningMode") as string;
                ds.Add(new InfoRow("Antivirus", "Microsoft Defender " + (B(P(mp, "AntivirusEnabled")) ? "on" : "off") + (mode != null ? " · mode " + mode : "")));
                ds.Add(new InfoRow("Real-time protection", B(P(mp, "RealTimeProtectionEnabled")) ? "On" : "Off"));
                ds.Add(new InfoRow("Tamper protection", B(P(mp, "IsTamperProtected")) ? "On" : "Off"));
                object age = P(mp, "AntivirusSignatureAge");
                ds.Add(new InfoRow("Antivirus signatures", (CimDate(P(mp, "AntivirusSignatureLastUpdated")) ?? "?") + (age != null ? " (" + age + " d)" : "") + " · " + P(mp, "AntivirusSignatureVersion")));
                string quick = CimDate(P(mp, "QuickScanEndTime")), full = CimDate(P(mp, "FullScanEndTime"));
                ds.Add(new InfoRow("Last quick / full scan", (quick ?? "never") + " / " + (full ?? "never")));
            }
            else ds.Add(new InfoRow("Antivirus", "Microsoft Defender not available"));
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"))
            {
                object v = k == null ? null : k.GetValue("OnboardingState");
                ds.Add(new InfoRow("Defender for Endpoint", v != null && Convert.ToInt32(v) == 1 ? "Device onboarded" : "Not onboarded"));
            }
            var av = Wmi(@"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct").Select(o => P(o, "displayName") as string).Where(n => n != null).Distinct().ToList();
            if (av.Count > 0) ds.Add(new InfoRow("Registered antivirus", string.Join(", ", av)));

            var vols = Wmi(@"root\cimv2\Security\MicrosoftVolumeEncryption", "SELECT DriveLetter,ProtectionStatus,EncryptionMethod,ConversionStatus FROM Win32_EncryptableVolume")
                .Where(v => P(v, "DriveLetter") != null).ToList();
            if (vols.Count > 0)
            {
                foreach (var v in vols)
                {
                    int prot = Convert.ToInt32(P(v, "ProtectionStatus") ?? 0), method = Convert.ToInt32(P(v, "EncryptionMethod") ?? 0), conv = Convert.ToInt32(P(v, "ConversionStatus") ?? 0);
                    string m = method == 3 ? "AES 128" : method == 4 ? "AES 256" : method == 6 ? "XTS-AES 128" : method == 7 ? "XTS-AES 256" : method == 0 ? "not encrypted" : "method " + method;
                    string c = conv == 1 ? "fully encrypted" : conv == 0 ? "fully decrypted" : conv == 2 ? "encryption in progress" : conv == 3 ? "decryption in progress" : "status " + conv;
                    st.Add(new InfoRow("BitLocker " + P(v, "DriveLetter"), (prot == 1 ? "Protection on" : "Protection off") + " · " + m + " · " + c));
                }
            }
            else st.Add(new InfoRow("BitLocker " + Environment.GetEnvironmentVariable("SystemDrive"), BitLockerFromShell()));

            var fw = Wmi(@"root\StandardCimv2", "SELECT Name,Enabled FROM MSFT_NetFirewallProfile");
            if (fw.Count > 0)
            {
                st.Add(new InfoRow("Firewall", string.Join("  ·  ", fw.Select(p =>
                {
                    string n = P(p, "Name") as string ?? "?";
                    return n + ": " + (Convert.ToInt32(P(p, "Enabled") ?? 0) == 1 ? "on" : "off");
                }))));
            }
            int fwRules = s.Items.Count(i => i.Area == "Firewall · FirewallRules");
            if (fwRules > 0) st.Add(new InfoRow("Firewall rules from Intune", fwRules.ToString()));

            using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
            {
                object v = k == null ? null : k.GetValue("UEFISecureBootEnabled");
                st.Add(new InfoRow("Secure Boot", v == null ? "Not supported / legacy BIOS" : Convert.ToInt32(v) == 1 ? "On" : "Off"));
            }

            var tpm = Wmi(@"root\cimv2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm").FirstOrDefault();
            if (tpm != null)
            {
                string spec = (P(tpm, "SpecVersion") as string ?? "").Split(',')[0].Trim();
                st.Add(new InfoRow("TPM", (B(P(tpm, "IsEnabled_InitialValue")) ? "Enabled" : "Not enabled") + (B(P(tpm, "IsActivated_InitialValue")) ? ", activated" : "") + (spec.Length > 0 ? " · version " + spec : "")));
            }
            else st.Add(new InfoRow("TPM", s.IsAdmin ? "Not detected" : "Requires administrator rights"));

            var dg = Wmi(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard").FirstOrDefault();
            if (dg != null)
            {
                int vbs = Convert.ToInt32(P(dg, "VirtualizationBasedSecurityStatus") ?? 0);
                var running = (P(dg, "SecurityServicesRunning") as Array ?? new int[0]).Cast<object>().Select(Convert.ToInt32).ToList();
                var services = new List<string>();
                if (running.Contains(1)) services.Add("Credential Guard");
                if (running.Contains(2)) services.Add("Memory integrity (HVCI)");
                if (running.Contains(3)) services.Add("System Guard Secure Launch");
                st.Add(new InfoRow("Virtualization-based security", (vbs == 2 ? "Running" : vbs == 1 ? "Enabled, not running" : "Off")
                    + (services.Count > 0 ? " · " + string.Join(", ", services) : "")));
            }

            var asr = s.Items.Where(i => i.Area == AsrArea).ToList();
            if (asr.Count > 0)
                ds.Add(new InfoRow("ASR rules", asr.Count(i => i.Value.StartsWith("Block")) + " block · " + asr.Count(i => i.Value.StartsWith("Audit")) + " audit · " + asr.Count(i => i.Value.StartsWith("Warn")) + " warn"));

            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
            {
                object v = k == null ? null : k.GetValue("EnableLUA");
                st.Add(new InfoRow("User Account Control (UAC)", v != null && Convert.ToInt32(v) == 0 ? "Off" : "On"));
            }

            string laps = "Not configured";
            using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\PolicyManager\current\device\LAPS"))
            using (var k2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Policies\LAPS"))
            using (var k3 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft Services\AdmPwd"))
            {
                if (k != null && k.ValueCount > 0) laps = "Configured by Intune (Windows LAPS)";
                else if (k2 != null && k2.ValueCount > 0) laps = "Configured (Windows LAPS)";
                else if (k3 != null && k3.ValueCount > 0) laps = "Configured (legacy LAPS)";
            }
            st.Add(new InfoRow("LAPS", laps));
        }

        // BitLocker status readable by standard users too (shell property)
        static string BitLockerFromShell()
        {
            try
            {
                dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
                object v = shell.NameSpace(17).ParseName(Environment.GetEnvironmentVariable("SystemDrive")).ExtendedProperty("System.Volume.BitLockerProtection");
                switch (v == null ? -1 : Convert.ToInt32(v))
                {
                    case 1: return "Protection on";
                    case 2: return "Protection off";
                    case 3: return "Encryption in progress";
                    case 4: return "Decryption in progress";
                    case 5: return "Protection suspended";
                    case 6: return "Locked";
                    default: return "Not available";
                }
            }
            catch { return "Not available"; }
        }

        #endregion
    }

    #endregion

    #region Windows Update setting descriptions

    static class Descriptions
    {
        static readonly Dictionary<string, string> Text = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "AllowAutoUpdate", "Automatic update behavior: download, install and restart handling." },
            { "AllowMUUpdateService", "Allows Windows Update to also deliver updates for other Microsoft products (e.g. Office)." },
            { "AllowUpdateService", "Allows the device to contact the Microsoft Update service." },
            { "ExcludeWUDriversInQualityUpdate", "Excludes drivers from Windows Update quality updates." },
            { "ExcludeWUDrivers", "Effective exclusion of drivers from quality updates." },
            { "ExcludeWUDriversInQualityUpdates", "Excludes drivers from Windows Update quality updates." },
            { "DeferQualityUpdatesPeriodInDays", "Days quality updates (monthly cumulative) are deferred after release." },
            { "DeferFeatureUpdatesPeriodInDays", "Days feature updates (new Windows version) are deferred after release." },
            { "DeferQualityUpdates", "Whether quality update deferral is active." },
            { "DeferFeatureUpdates", "Whether feature update deferral is active." },
            { "QualityUpdatesDeferralInDays", "Quality update deferral actually applied by the client (days)." },
            { "FeatureUpdatesDeferralInDays", "Feature update deferral actually applied by the client (days)." },
            { "PauseQualityUpdates", "Temporary pause of quality updates." },
            { "PauseFeatureUpdates", "Temporary pause of feature updates." },
            { "PauseQualityUpdatesStartTime", "Start date of the quality update pause." },
            { "PauseFeatureUpdatesStartTime", "Start date of the feature update pause." },
            { "SetEDURestart", "Restart mode for education devices: restart only outside active hours and with no users signed in." },
            { "ActiveHoursStart", "Start of active hours: during this window Windows does not restart the PC automatically." },
            { "ActiveHoursEnd", "End of active hours." },
            { "ActiveHoursMaxRange", "Maximum length the user can set for active hours." },
            { "ConfigureFeatureUpdateUninstallPeriod", "Days during which a feature update can be uninstalled to go back to the previous version." },
            { "SetDisablePauseUXAccess", "If on, hides the \"Pause updates\" option from the user." },
            { "SetDisableUXWUAccess", "If on, prevents the user from using Windows Update features (manual scan and download)." },
            { "BranchReadinessLevel", "Release channel the device receives feature updates from." },
            { "ManagePreviewBuilds", "Management of preview builds (Windows Insider Program)." },
            { "ConfigureDeadlineForFeatureUpdates", "Days after which installing a feature update and restarting become mandatory." },
            { "ConfigureDeadlineForQualityUpdates", "Days after which installing a quality update and restarting become mandatory." },
            { "ConfigureDeadlineGracePeriod", "Grace days after the deadline before a forced restart (quality updates)." },
            { "ConfigureDeadlineGracePeriodForFeatureUpdates", "Grace days after the deadline before a forced restart (feature updates)." },
            { "ConfigureDeadlineNoAutoReboot", "If on, the PC does not restart automatically before the configured deadline." },
            { "ScheduleImminentRestartWarning", "Warning time before an imminent restart." },
            { "ScheduleRestartWarning", "Warning time before a scheduled restart." },
            { "UpdateNotificationLevel", "Level of Windows Update notifications shown to the user." },
            { "AllowRebootlessUpdates", "Allows updates without restart (hotpatch), where supported." },
            { "DriverUpdateEnrolled", "Device enrolled in the Windows Update for Business deployment service (Intune/Autopatch) for drivers." },
            { "FeatureUpdateEnrolled", "Device enrolled in the Windows Update for Business deployment service for feature updates." },
            { "QualityUpdateEnrolled", "Device enrolled in the Windows Update for Business deployment service for quality updates (e.g. expedited releases)." },
            { "QuickMachineRecoveryEnrolled", "Enrollment in Quick Machine Recovery." },
            { "TargetReleaseVersion", "Target Windows version: the PC stays on or moves to this version." },
            { "TargetReleaseVersionInfo", "Target Windows version (e.g. 24H2)." },
            { "ProductVersion", "Target product for feature updates (e.g. Windows 11)." },
            { "WUServer", "WSUS server updates are downloaded from." },
            { "UpdateServiceUrl", "WSUS server updates are downloaded from." },
            { "WUStatusServer", "WSUS server reports are sent to." },
            { "UseWUServer", "If 1, the PC uses the WSUS server set in WUServer." },
            { "NoAutoUpdate", "If 1, automatic updates are turned off." },
            { "AUOptions", "Automatic update mode set by GPO." },
            { "ScheduledInstallDay", "Scheduled install day." },
            { "ScheduledInstallTime", "Scheduled install time." },
            { "DisableDualScan", "Prevents scanning against Windows Update when WSUS is configured." },
            { "DoNotConnectToWindowsUpdateInternetLocations", "Prevents connecting to Windows Update Internet locations." },
            { "SetPolicyDrivenUpdateSourceForFeatureUpdates", "Source for feature updates (Windows Update or WSUS)." },
            { "SetPolicyDrivenUpdateSourceForQualityUpdates", "Source for quality updates (Windows Update or WSUS)." },
            { "SetPolicyDrivenUpdateSourceForDriverUpdates", "Source for driver updates (Windows Update or WSUS)." },
            { "SetPolicyDrivenUpdateSourceForOtherUpdates", "Source for other updates (Windows Update or WSUS)." },
            { "IsWUfBConfigured", "Whether Windows Update for Business is configured." },
            { "IsWUfBDualScanActive", "Whether dual scan (WSUS + Windows Update) is active." },
            { "IsDeferralIsActive", "Whether an update deferral is active." },
            { "UseUpdateClassPolicySource", "Whether sources are defined per update class." },
            { "PolicySources", "Update policy sources detected by the client (internal value)." },
            { "AllowTemporaryEnterpriseFeatureControl", "Enables features introduced by monthly updates that would otherwise stay off on managed PCs." },
            { "TemporaryEnterpriseFeatureControlState", "State of the control over features introduced by monthly updates." },
            { "AllowOptionalContent", "Handling of optional content and gradually rolled-out features." },
            { "DODownloadMode", "Delivery Optimization mode (peer-to-peer download sharing)." },
            { "NoAutoRebootWithLoggedOnUsers", "If 1, no automatic restart while users are signed in." },
        };

        static readonly Dictionary<string, Dictionary<int, string>> Maps = new Dictionary<string, Dictionary<int, string>>(StringComparer.OrdinalIgnoreCase)
        {
            { "AllowAutoUpdate", new Dictionary<int, string> { { 0, "Notify before download" }, { 1, "Auto install, user schedules restart" }, { 2, "Auto install and restart" }, { 3, "Auto install and restart at scheduled time" }, { 4, "Auto install and restart without end-user control" }, { 5, "Automatic updates off" }, { 6, "Auto install with user schedule" } } },
            { "AUOptions", new Dictionary<int, string> { { 2, "Notify for download and install" }, { 3, "Auto download, notify for install" }, { 4, "Auto download and schedule install" }, { 5, "Allow local admin to choose" }, { 7, "Auto download, notify for install and restart" } } },
            { "BranchReadinessLevel", new Dictionary<int, string> { { 2, "Windows Insider – Canary/Dev" }, { 4, "Windows Insider – Beta" }, { 8, "Windows Insider – Release Preview" }, { 16, "General Availability Channel" }, { 32, "Semi-Annual Channel (legacy)" } } },
            { "ManagePreviewBuilds", new Dictionary<int, string> { { 0, "Preview builds disabled" }, { 1, "Disabled at next public release" }, { 2, "Preview builds enabled" }, { 3, "Left to the user" } } },
            { "UpdateNotificationLevel", new Dictionary<int, string> { { 0, "Default notifications" }, { 1, "Restart warnings only" }, { 2, "No notifications, including restart warnings" } } },
            { "ScheduledInstallDay", new Dictionary<int, string> { { 0, "Every day" }, { 1, "Sunday" }, { 2, "Monday" }, { 3, "Tuesday" }, { 4, "Wednesday" }, { 5, "Thursday" }, { 6, "Friday" }, { 7, "Saturday" } } },
            { "DODownloadMode", new Dictionary<int, string> { { 0, "HTTP only" }, { 1, "Peers on same LAN" }, { 2, "Peers in group" }, { 3, "Internet peers" }, { 99, "Simple (no peers)" }, { 100, "Bypass (BITS)" } } },
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

        // Translates a known numeric value into readable text; null if there is no translation
        public static string Decode(string name, object raw)
        {
            if (raw == null || name == null) return null;
            int v;
            if (raw is int) v = (int)raw;
            else if (!(raw is string) || !int.TryParse((string)raw, out v)) return null;

            Dictionary<int, string> map;
            string text;
            if (Maps.TryGetValue(name, out map) && map.TryGetValue(v, out text)) return text + " (" + v + ")";
            if (Booleans.Contains(name)) return v == 0 ? "No (0)" : v == 1 ? "Yes (1)" : v.ToString();
            if (name.StartsWith("SetPolicyDrivenUpdateSourceFor", StringComparison.OrdinalIgnoreCase))
                return v == 0 ? "Windows Update (0)" : v == 1 ? "WSUS (1)" : "Not configured";
            if (name.EndsWith("InDays", StringComparison.OrdinalIgnoreCase) || name.StartsWith("ConfigureDeadline", StringComparison.OrdinalIgnoreCase) || name == "ConfigureFeatureUpdateUninstallPeriod")
                return v + (v == 1 ? " day" : " days");
            if (name == "ActiveHoursStart" || name == "ActiveHoursEnd" || name == "ScheduledInstallTime") return v.ToString("00") + ":00";
            if (name == "ActiveHoursMaxRange") return v + " hours";
            if (name == "ScheduleImminentRestartWarning") return v + " minutes";
            if (name == "ScheduleRestartWarning") return v + " hours";
            return null;
        }
    }

    #endregion

    #region Anonymization

    static class Anonymizer
    {
        const string Hidden = "(hidden)";

        public static void Apply(Snapshot s)
        {
            var map = new List<KeyValuePair<string, string>>();
            Action<string, string> add = delegate (string from, string to)
            {
                if (!string.IsNullOrEmpty(from) && from.Length > 2 && from != "—") map.Add(new KeyValuePair<string, string>(from, to));
            };
            add(s.UserName, @"CONTOSO\user");
            if (s.UserName != null && s.UserName.Contains("\\"))
            {
                add(s.UserName.Split('\\')[0], "CONTOSO");
                add(s.UserName.Split('\\')[1], "user");
            }
            add(Environment.UserName, "user");
            add(Environment.UserDomainName, "CONTOSO");
            add(s.UserSid, "S-1-12-1-0000000000-0000000000-0000000000-0000000000");
            add(s.ComputerName, "PC-DEMO01");
            foreach (var r in s.Device)
            {
                if (r.Label == "Serial number") add(r.Value, "XXXXXXXXXX");
                if (r.Label == "Tenant") add(r.Value, "Contoso");
            }
            foreach (string id in s.Providers.Keys) add(id, "00000000-0000-0000-0000-000000000000");
            map = map.OrderByDescending(kv => kv.Key.Length).ToList();

            Func<string, string> fix = delegate (string t)
            {
                if (string.IsNullOrEmpty(t)) return t;
                foreach (var kv in map) t = Regex.Replace(t, Regex.Escape(kv.Key), kv.Value.Replace("$", "$$"), RegexOptions.IgnoreCase);
                t = Regex.Replace(t, @"[\w.+-]+@[\w-]+(\.[\w-]+)+", "user@contoso.com");
                t = Regex.Replace(t, @"https?://[^\s;""<>]+", "https://contoso.example/...");
                // Tenant ID in Office keys (e.g. "<tenantId>_ADAL")
                t = Regex.Replace(t, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=_ADAL)", "00000000-0000-0000-0000-000000000000");
                return t;
            };

            s.ComputerName = fix(s.ComputerName);
            s.UserName = fix(s.UserName);
            foreach (var r in s.Device.Concat(s.Management).Concat(s.UpdateStatus).Concat(s.SecurityStatus).Concat(s.DefenderStatus))
            {
                r.Label = fix(r.Label);
                r.Value = fix(r.Value);
            }
            foreach (var g in s.Gpos) { g.Name = fix(g.Name); g.Link = fix(g.Link); }
            for (int i = 0; i < s.Warnings.Count; i++) s.Warnings[i] = fix(s.Warnings[i]);
            int fwRule = 0;
            foreach (var i in s.Items)
            {
                // Firewall rule names reveal company applications and vendors
                if (i.Area.StartsWith("Firewall")) i.Name = "Firewall rule " + (++fwRule);
                i.Name = fix(i.Name); i.Value = fix(i.Value); i.Details = fix(i.Details); i.Path = fix(i.Path);
                i.Source = fix(i.Source); i.SourceShort = fix(i.SourceShort); i.Area = fix(i.Area); i.Description = fix(i.Description);
                // Exclusions and firewall rules describe the company security configuration
                if (i.Area == Security.ExclusionsArea || i.Area.StartsWith("Firewall")) { i.Value = Hidden; i.Details = Hidden; }
                // Values that identify a person (e.g. Office "LastLoggedInUserDisplayName")
                if (!i.Name.StartsWith("Dont", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(i.Name ?? "", "DisplayName|UserName|LoggedInUser|EmailAddress|UserEmail|Upn$|^Owner|AccountName|UserPrincipal|LegalNotice|MessageText|MessageTitle", RegexOptions.IgnoreCase)) { i.Value = Hidden; i.Details = Hidden; }
            }
        }
    }

    #endregion

    #region HTML report

    static class Report
    {
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static void WriteHtml(Snapshot s, string path)
        {
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.Append("<title>Policies " + H(s.ComputerName) + "</title><style>");
            sb.Append(":root{--bg:#f4f6fa;--card:#fff;--line:#e5e9f0;--text:#0f172a;--muted:#64748b;--accent:#2563eb}");
            sb.Append("@media (prefers-color-scheme:dark){:root{--bg:#0f141d;--card:#171e2a;--line:#273142;--text:#e2e8f0;--muted:#94a3b8;--accent:#60a5fa}}");
            sb.Append("*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 'Segoe UI',system-ui,sans-serif}");
            sb.Append("header{padding:28px 32px 8px}h1{margin:0;font-size:26px;font-weight:600}header p{margin:4px 0 0;color:var(--muted)}");
            sb.Append("main{padding:16px 32px 40px;max-width:1400px}section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}");
            sb.Append("h2{font-size:16px;margin:0 0 12px}h3{font-size:13px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}");
            sb.Append("table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}");
            sb.Append("th{color:var(--muted);font-size:12px;font-weight:600}td.k{color:var(--muted);width:240px}.b{display:inline-block;padding:1px 9px;border-radius:10px;font-size:12px;font-weight:600;background:#e6eefd;color:#1d4ed8}");
            sb.Append(".GPO{background:#f3e8ff;color:#7e22ce}.REG{background:#eef1f5;color:#475569}.WU{background:#ddf5ef;color:#0f766e}.EFF{background:#fef3c7;color:#b45309}.desc{color:var(--muted);font-size:12.5px}");
            sb.Append("#q{width:100%;max-width:420px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font:inherit;margin-bottom:6px}");
            sb.Append(".warn{background:#fff8eb;border-color:#f6d58e;color:#7c4a03}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:900px){.grid2{grid-template-columns:1fr}td.k{width:auto}}");
            sb.Append("</style></head><body><header><h1>Applied policies · " + H(s.ComputerName) + "</h1><p>User " + H(s.UserName) + " · collected " + s.CollectedAt.ToString(Fmt.DateTime) + (s.IsAdmin ? "" : " · run without administrator rights") + "</p></header><main>");
            sb.Append("<input id=\"q\" placeholder=\"Filter tables…\" oninput=\"f(this.value)\">");

            if (s.Warnings.Count > 0)
            {
                sb.Append("<section class=\"warn\"><h2>Warnings</h2>");
                foreach (var w in s.Warnings) sb.Append("<div>" + H(w) + "</div>");
                sb.Append("</section>");
            }

            sb.Append("<div class=\"grid2\">");
            InfoSection(sb, "Device", s.Device);
            InfoSection(sb, "Management and sync", s.Management);
            sb.Append("</div><div class=\"grid2\"><section><h2>Group Policy (GPO)</h2><table>");
            if (s.Gpos.Count == 0) sb.Append("<tr><td>No Group Policy Objects found.</td></tr>");
            foreach (var g in s.Gpos) sb.Append("<tr><td class=\"k\">" + H(g.Scope) + "</td><td><b>" + H(g.Name) + "</b><div class=\"desc\">" + H(g.Link) + "</div></td></tr>");
            sb.Append("</table></section>");
            InfoSection(sb, "Windows Update at a glance", s.UpdateStatus);
            sb.Append("</div><div class=\"grid2\">");
            InfoSection(sb, "Security at a glance", s.SecurityStatus);
            InfoSection(sb, "Microsoft Defender at a glance", s.DefenderStatus);
            sb.Append("</div>");

            PolicySection(sb, "User policies", s.UserItems);
            PolicySection(sb, "Machine policies", s.MachineItems);
            PolicySection(sb, "Security policies", s.SecurityItems);
            PolicySection(sb, "Microsoft Defender", s.DefenderItems);
            PolicySection(sb, "Update policies", s.UpdateItems);

            sb.Append("<section><h2>Windows Update history</h2><table class=\"f\"><tr><th>Date</th><th>Update</th><th>Operation</th><th>Result</th></tr>");
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
                sb.Append("<h3>" + H(g.Key) + "</h3><table class=\"f\"><tr><th style=\"width:32%\">Name</th><th style=\"width:38%\">Value</th><th>Source</th></tr>");
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

    #region User interface

    class MainWindow : Window
    {
        readonly FrameworkElement root;
        readonly string screenshotDir;
        readonly bool anonymize;
        Snapshot data;
        string page = "summary";
        string kindFilter = "";
        ListCollectionView policyView, historyView;

        readonly DataGrid policyGrid, historyGrid;
        readonly TextBox searchBox;

        public MainWindow(string screenshotDir, bool anonymize)
        {
            this.screenshotDir = screenshotDir;
            this.anonymize = anonymize;
            Title = "Policy Viewer";
            // On laptops with 125-150% scaling the work area is often below 1360x860 DIP: a window larger
            // than the screen cannot be centered, so the size is fitted to the work area
            var work = SystemParameters.WorkArea;
            Width = Math.Min(1360, work.Width * 0.94);
            Height = Math.Min(860, work.Height * 0.94);
            MinWidth = Math.Min(1000, Width);
            MinHeight = Math.Min(600, Height);
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
            NavHook("NavSecurity", "security");
            NavHook("NavDefender", "defender");
            NavHook("NavUpdates", "updates");
            NavHook("NavHistory", "history");
            CardHook("CardUser", "NavUser");
            CardHook("CardMachine", "NavMachine");
            CardHook("CardSecurity", "NavSecurity");
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
                if (anonymize) Anonymizer.Apply(t.Result);
                Apply(t.Result);
                if (screenshotDir != null) Dispatcher.BeginInvoke(new Action(TakeScreenshots), DispatcherPriority.ApplicationIdle);
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        void Apply(Snapshot s)
        {
            data = s;
            F<TextBlock>("SideComputer").Text = s.ComputerName;
            int userMdm = s.UserItems.Count(i => i.SourceKind == "MDM"), userGpo = s.UserItems.Count(i => i.SourceKind == "GPO"), userReg = s.UserItems.Count(i => i.SourceKind == "REG");
            int machMdm = s.MachineItems.Count(i => i.SourceKind == "MDM"), machGpo = s.MachineItems.Count(i => i.SourceKind == "GPO"), machReg = s.MachineItems.Count(i => i.SourceKind == "REG");
            F<TextBlock>("StatUser").Text = s.UserItems.Count().ToString();
            F<TextBlock>("StatUserSub").Text = string.Format("Intune {0} · GPO {1} · Registry {2}", userMdm, userGpo, userReg);
            F<TextBlock>("StatMachine").Text = s.MachineItems.Count().ToString();
            F<TextBlock>("StatMachineSub").Text = string.Format("Intune {0} · GPO {1} · Registry {2}", machMdm, machGpo, machReg);
            int sec = s.SecurityItems.Count(), def = s.DefenderItems.Count();
            F<TextBlock>("StatSecurity").Text = (sec + def).ToString();
            F<TextBlock>("StatSecuritySub").Text = string.Format("Security {0} · Defender {1}", sec, def);
            F<TextBlock>("StatUpdates").Text = s.UpdateItems.Count().ToString();
            F<TextBlock>("StatUpdatesSub").Text = string.Format("Intune {0} · WUfB DS {1} · effective state {2}",
                s.UpdateItems.Count(i => i.SourceKind == "MDM"), s.UpdateItems.Count(i => i.Source == "WUfB Deployment Service"), s.UpdateItems.Count(i => i.SourceShort == "WU state"));
            var installed = s.History.Where(h => h.ResultKind == "OK" && h.Operation == "Install").ToList();
            F<TextBlock>("StatHistory").Text = installed.Count.ToString();
            F<TextBlock>("StatHistorySub").Text = installed.Count > 0 ? "Latest: " + installed[0].Date.ToString(Fmt.Date) : "No installs recorded";

            F<ItemsControl>("DeviceList").ItemsSource = s.Device;
            F<ItemsControl>("MdmList").ItemsSource = s.Management;
            F<ItemsControl>("GpoList").ItemsSource = s.Gpos;
            F<FrameworkElement>("GpoEmpty").Visibility = s.Gpos.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            F<ItemsControl>("UpdateSummaryList").ItemsSource = s.UpdateStatus;
            F<ItemsControl>("SecuritySummaryList").ItemsSource = s.DefenderStatus.Concat(s.SecurityStatus).ToList();
            F<ItemsControl>("WarningList").ItemsSource = s.Warnings;
            F<FrameworkElement>("WarningCard").Visibility = s.Warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("BtnElevate").Visibility = s.IsAdmin ? Visibility.Collapsed : Visibility.Visible;
            F<TextBlock>("SideFooter").Text = "Collected: " + s.CollectedAt.ToString(Fmt.DateTime) + "\nAdministrator: " + (s.IsAdmin ? "yes" : "no") + "\nUser: " + s.UserName;

            historyView = new ListCollectionView(s.History);
            historyView.Filter = o => MatchesSearch(((HistoryItem)o).SearchText);
            historyGrid.ItemsSource = historyView;
            ShowPage(page);
        }

        static readonly Dictionary<string, string[]> PageText = new Dictionary<string, string[]>
        {
            { "summary", new[] { "Summary", "Overview of the policies applied to this PC and its management status." } },
            { "user", new[] { "User policies", "Settings applied to the signed-in user by Intune, Group Policy and Policies registry keys (HKCU)." } },
            { "machine", new[] { "Machine policies", "Settings applied to the device by Intune, Group Policy and Policies registry keys (HKLM). Windows Update policies are under Updates." } },
            { "security", new[] { "Security policies", "BitLocker, firewall, LAPS, Device Guard, security options, account policies and user rights: configured by Intune/GPO and effective values." } },
            { "defender", new[] { "Microsoft Defender", "Defender policies deployed by Intune/GPO, effective antivirus configuration, ASR rules and exclusions." } },
            { "updates", new[] { "Update policies", "Update rings, deferrals, deadlines and Windows Update effective state." } },
            { "history", new[] { "Update history", "Latest installs recorded by Windows Update on this PC." } },
        };

        void ShowPage(string key)
        {
            page = key;
            F<TextBlock>("PageTitle").Text = PageText[key][0];
            F<TextBlock>("PageSubtitle").Text = PageText[key][1];
            bool policies = key == "user" || key == "machine" || key == "security" || key == "defender" || key == "updates";
            F<FrameworkElement>("PageSummary").Visibility = key == "summary" ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("PagePolicies").Visibility = policies ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("PageHistory").Visibility = key == "history" ? Visibility.Visible : Visibility.Collapsed;
            F<FrameworkElement>("Toolbar").Visibility = key == "summary" ? Visibility.Collapsed : Visibility.Visible;
            F<FrameworkElement>("Chips").Visibility = policies ? Visibility.Visible : Visibility.Collapsed;
            var cards = F<ItemsControl>("StatusCards");
            cards.Visibility = key == "updates" || key == "security" || key == "defender" ? Visibility.Visible : Visibility.Collapsed;
            if (data == null) return;
            cards.ItemsSource = key == "updates" ? data.UpdateStatus : key == "security" ? data.SecurityStatus : key == "defender" ? data.DefenderStatus : null;

            if (policies)
            {
                var source = key == "user" ? data.UserItems : key == "machine" ? data.MachineItems : key == "security" ? data.SecurityItems
                    : key == "defender" ? data.DefenderItems : data.UpdateItems;
                var items = source
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
            string[] kinds = { "", "MDM", "GPO", "REG", "WU", "EFF" };
            string[] labels = { "All", "Intune", "GPO", "Registry", "Windows Update", "Effective state" };
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
            if (page == "history" && historyView != null) count.Text = historyView.Count + " of " + data.History.Count + " entries";
            else if (policyView != null && page != "summary")
            {
                count.Text = policyView.Count + " of " + policyView.SourceCollection.Cast<object>().Count() + " settings";
                F<FrameworkElement>("GridEmpty").Visibility = policyView.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        // Column sorting that keeps the grouping by area
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
            string text = string.Format("Name: {0}\r\nValue: {1}\r\nDescription: {2}\r\nArea: {3}\r\nSource: {4}\r\nPath: {5}\r\n\r\n{6}",
                i.Name, i.Value, i.DescriptionText, i.Area, i.Source, i.Path, (i.Details ?? "").Replace("\n", "\r\n"));
            try { Clipboard.SetText(text); } catch { }
        }

        void Export()
        {
            if (data == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export policy report",
                Filter = "HTML report (*.html)|*.html",
                FileName = "Policy_" + data.ComputerName + "_" + data.CollectedAt.ToString("yyyyMMdd_HHmm") + ".html",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                Report.WriteHtml(data, dlg.FileName);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
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

        // Test only: saves one PNG per page and closes
        void TakeScreenshots()
        {
            Directory.CreateDirectory(screenshotDir);
            var navs = new[] { "NavSummary", "NavUser", "NavMachine", "NavSecurity", "NavDefender", "NavUpdates", "NavHistory" };
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
