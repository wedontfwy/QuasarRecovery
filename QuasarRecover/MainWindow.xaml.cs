using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Windows;

namespace QuasarRecover
{
    public partial class MainWindow : Window
    {
        private string _assemblyPath = "";
        private string _lastJson = "{ }";

        public MainWindow()
        {
            InitializeComponent();
        }

        private void OpenAssemblyButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog
            {
                Title = "Select Quasar client executable",
                Filter = ".NET Assembly (*.exe;*.dll)|*.exe;*.dll|All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                _assemblyPath = dialog.FileName;
                AssemblyPathTextBox.Text = _assemblyPath;
                AppendLog("Selected: " + _assemblyPath);
                FooterStatusText.Text = "Assembly loaded. Ready to analyze.";
            }
        }

        private void AnalyzeButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_assemblyPath) || !File.Exists(_assemblyPath))
            {
                MessageBox.Show("Please select a valid assembly first.");
                return;
            }

            try
            {
                AppendLog("Starting read-only static analysis...");

                _lastJson = QuasarRecoveryAnalyzer.AnalyzeToJson(_assemblyPath);
                JsonOutputTextBox.Text = _lastJson;

                JObject report = JObject.Parse(_lastJson);


                JObject status = report["RecoveryStatus"] as JObject;
                JObject settings = report["Settings"] as JObject;

                bool settingsFound = GetBool(status, "SettingsClassFound");
                bool hostsFieldFound = GetBool(status, "HostsFieldFound");
                bool certificateFound = GetBool(status, "CertificateFieldFound");
                bool encryptionKeyFound = GetBool(status, "EncryptionKeyFound");

                string hosts = Get(settings, "Hosts");
                string version = Get(settings, "Version");
                string installName = Get(settings, "InstallName");
                string subDirectory = Get(settings, "SubDirectory");
                string mutex = Get(settings, "Mutex");
                string tag = Get(settings, "Tag");
                string startupKey = Get(settings, "StartupKey");

                SettingsStatusText.Text = settingsFound
                    ? "Settings class: Found"
                    : "Settings class: Not found";

                HostsStatusText.Text = !string.IsNullOrWhiteSpace(hosts)
                    ? "Hosts: " + hosts
                    : hostsFieldFound
                        ? "Hosts: Encrypted candidate found"
                        : "Hosts: Not found";

                CertificateStatusText.Text = certificateFound
                    ? "Certificate: Candidate found"
                    : "Certificate: Not found";

                SignatureStatusText.Text = encryptionKeyFound
                    ? "Signature/crypto: Candidate found"
                    : "Signature/crypto: Not found";

                RecoveredHostsText.Text = "Hosts: " + Dash(hosts);
                RecoveredVersionText.Text = "Version: " + Dash(version);
                RecoveredInstallText.Text = "Install: " + Dash(CombineInstall(subDirectory, installName));
                RecoveredMutexText.Text = "Mutex: " + Dash(mutex);
                RecoveredTagText.Text = "Tag: " + Dash(tag);
                RecoveredStartupText.Text = "Startup key: " + Dash(startupKey);

                AppendLog("Analysis complete.");

                AppendSetting(settings, "Hosts");
                AppendSetting(settings, "Version");
                AppendSetting(settings, "InstallName");
                AppendSetting(settings, "SubDirectory");
                AppendSetting(settings, "Mutex");
                AppendSetting(settings, "StartupKey");
                AppendSetting(settings, "Tag");
                AppendSetting(settings, "LogDirectoryName");
                AppendSetting(settings, "EncryptionKey");

                FooterStatusText.Text = "Analysis complete.";
            }
            catch (Exception ex)
            {
                AppendLog("Analysis failed: " + ex.Message);
                MessageBox.Show(ex.Message, "Analysis failed");
            }
        }


    

        private static bool GetBool(JObject obj, string name)
        {
            return obj?[name]?.Value<bool>() == true;
        }

        private static string Dash(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }

        private static string CombineInstall(string subDirectory, string installName)
        {
            if (string.IsNullOrWhiteSpace(subDirectory))
                return installName;

            if (string.IsNullOrWhiteSpace(installName))
                return subDirectory;

            return subDirectory.TrimEnd('\\') + "\\" + installName;
        }

        private void AppendSetting(JObject settings, string name)
        {
            string value = Get(settings, name);

            if (!string.IsNullOrWhiteSpace(value))
                AppendLog(name + ": " + value);
        }



        private static string Get(JObject obj, string name)
        {
            return obj?[name]?.ToString();
        }
        private void ExportJsonButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog dialog = new SaveFileDialog
            {
                Title = "Export recovered JSON",
                Filter = "JSON File (*.json)|*.json",
                FileName = "quasar-recovery-report.json"
            };

            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, _lastJson);
                AppendLog("Exported JSON: " + dialog.FileName);
                FooterStatusText.Text = "JSON exported.";
            }
        }

        private void AppendLog(string message)
        {
            LogTextBox.AppendText(Environment.NewLine + "- [" + DateTime.Now.ToString("HH:mm:ss") + "] " + message);
            LogTextBox.ScrollToEnd();
        }
    }
}
