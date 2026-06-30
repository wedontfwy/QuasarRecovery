using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace QuasarRecover
{
    public static class QuasarRecoveryAnalyzer
    {
        public static string AnalyzeToJson(string path)
        {
            ModuleDefMD module = ModuleDefMD.Load(path);

            TypeDef appType = FindApplicationRunTarget(module);
            TypeDef settingsType = appType != null ? FindSettingsTypeFromApp(appType) : null;

            if (settingsType == null)
                settingsType = FindSettingsFallback(module.GetTypes().ToList());

            QuasarSettingsReport report = new QuasarSettingsReport
            {
                Project = "QuasarRecover",
                Mode = "read-only static analysis",
                AssemblyPath = path,
                AssemblyName = module.Assembly != null ? module.Assembly.Name.String : Path.GetFileName(path),
                EntryPoint = module.EntryPoint != null
                    ? module.EntryPoint.DeclaringType.FullName + "::" + module.EntryPoint.Name
                    : null,
                ApplicationType = appType != null ? appType.FullName : null,
                SettingsType = settingsType != null ? settingsType.FullName : null,
                SettingsFound = settingsType != null
            };

            if (settingsType != null)
                ExtractQuasarSettings(settingsType, report);

            return JsonConvert.SerializeObject(report, Formatting.Indented);
        }

        private static TypeDef FindApplicationRunTarget(ModuleDefMD module)
        {
            MethodDef entry = module.EntryPoint;
            if (entry == null || !entry.HasBody) return null;

            TypeDef lastNewObjectType = null;

            foreach (Instruction ins in entry.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Newobj)
                {
                    IMethod ctor = ins.Operand as IMethod;
                    if (ctor != null)
                        lastNewObjectType = ctor.DeclaringType.ResolveTypeDef();
                }

                if (ins.OpCode == OpCodes.Call)
                {
                    IMethod call = ins.Operand as IMethod;

                    if (call != null &&
                        call.DeclaringType.FullName == "System.Windows.Forms.Application" &&
                        call.Name == "Run")
                    {
                        return lastNewObjectType;
                    }
                }
            }

            return null;
        }

        private static TypeDef FindSettingsTypeFromApp(TypeDef appType)
        {
            foreach (MethodDef method in appType.Methods)
            {
                if (!method.HasBody) continue;

                foreach (Instruction ins in method.Body.Instructions)
                {
                    if (ins.OpCode != OpCodes.Call) continue;

                    IMethod call = ins.Operand as IMethod;
                    if (call == null || call.MethodSig == null) continue;
                    if (call.MethodSig.RetType.FullName != "System.Boolean") continue;

                    TypeDef declaringType = call.DeclaringType.ResolveTypeDef();
                    if (declaringType != null && LooksLikeQuasarSettings(declaringType))
                        return declaringType;
                }
            }

            return null;
        }

        private static TypeDef FindSettingsFallback(List<TypeDef> types)
        {
            TypeDef best = null;
            int bestScore = 0;

            foreach (TypeDef type in types)
            {
                int score = 0;

                if (type.Fields.Count(f => f.IsStatic && f.FieldType.FullName == "System.String") >= 8) score += 3;
                if (type.Fields.Any(f => f.IsStatic && f.FieldType.FullName.Contains("X509Certificate2"))) score += 5;
                if (TypeUses(type, "System.Convert::FromBase64String")) score += 3;
                if (TypeUses(type, "System.IO.Path::Combine")) score += 2;
                if (TypeUses(type, "System.Environment::GetFolderPath")) score += 2;
                if (TypeUses(type, "VerifyHash")) score += 2;

                if (score > bestScore)
                {
                    bestScore = score;
                    best = type;
                }
            }

            return bestScore >= 8 ? best : null;
        }

        private static bool LooksLikeQuasarSettings(TypeDef type)
        {
            return
                type.Fields.Count(f => f.IsStatic && f.FieldType.FullName == "System.String") >= 8 &&
                type.Fields.Any(f => f.IsStatic && f.FieldType.FullName.Contains("X509Certificate2")) &&
                TypeUses(type, "System.Convert::FromBase64String") &&
                TypeUses(type, "System.IO.Path::Combine") &&
                TypeUses(type, "System.Environment::GetFolderPath");
        }
        private static string TryDecrypt(Aes256 aes, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            try
            {
                return aes.Decrypt(value);
            }
            catch
            {
                return null;
            }
        }
        private static void ExtractQuasarSettings(TypeDef settingsType, QuasarSettingsReport report)
        {
            List<StringFieldAssignment> strings = ExtractStaticStringAssignments(settingsType);
            List<BoolFieldAssignment> bools = ExtractStaticBoolAssignments(settingsType);
            List<IntFieldAssignment> ints = ExtractStaticIntAssignments(settingsType);

            report.RawStringFields = strings;
            report.RawBoolFields = bools;
            report.RawIntFields = ints;

            SetByIndex(strings, 0, v => report.Settings.VersionRaw = v);
            SetByIndex(strings, 1, v => report.Settings.HostsRaw = v);
            SetByIndex(strings, 2, v => report.Settings.SubDirectoryRaw = v);
            SetByIndex(strings, 3, v => report.Settings.InstallNameRaw = v);
            SetByIndex(strings, 4, v => report.Settings.MutexRaw = v);
            SetByIndex(strings, 5, v => report.Settings.StartupKeyRaw = v);

            string encryptionKey = strings.Select(x => x.Value).FirstOrDefault(LooksLikeSha1Hex);
            report.Settings.EncryptionKey = encryptionKey;

            if (!string.IsNullOrWhiteSpace(encryptionKey))
            {
                try
                {
                    var aes = new Aes256(encryptionKey);

                    report.Settings.Version =
                        TryDecrypt(aes, report.Settings.VersionRaw);

                    report.Settings.Hosts =
                        TryDecrypt(aes, report.Settings.HostsRaw);

                    report.Settings.SubDirectory =
                        TryDecrypt(aes, report.Settings.SubDirectoryRaw);

                    report.Settings.InstallName =
                        TryDecrypt(aes, report.Settings.InstallNameRaw);

                    report.Settings.Mutex =
                        TryDecrypt(aes, report.Settings.MutexRaw);

                    report.Settings.StartupKey =
                        TryDecrypt(aes, report.Settings.StartupKeyRaw);
                }
                catch
                {
                }
            }
            if (encryptionKey != null)
            {
                int encryptionIndex = strings.FindIndex(x => x.Value == encryptionKey);

                if (encryptionIndex + 1 < strings.Count) report.Settings.TagRaw = strings[encryptionIndex + 1].Value;
                if (encryptionIndex + 2 < strings.Count) report.Settings.LogDirectoryNameRaw = strings[encryptionIndex + 2].Value;


                try
                {
                    var aes = new Aes256(encryptionKey);

                    report.Settings.Tag =
                        TryDecrypt(aes, report.Settings.TagRaw);

                    report.Settings.LogDirectoryName =
                        TryDecrypt(aes, report.Settings.LogDirectoryNameRaw);
                }
                catch
                {
                }

                if (encryptionIndex + 3 < strings.Count) report.Settings.ServerSignatureRaw = strings[encryptionIndex + 3].Value;
                if (encryptionIndex + 4 < strings.Count) report.Settings.ServerCertificateStrRaw = strings[encryptionIndex + 4].Value;
            }

            FieldDef certField = settingsType.Fields.FirstOrDefault(f =>
                f.IsStatic && f.FieldType.FullName.Contains("X509Certificate2"));

            report.Settings.ServerCertificateField = certField != null ? certField.Name.String : null;

            IntFieldAssignment reconnectDelay = ints.FirstOrDefault();
            if (reconnectDelay != null)
                report.Settings.ReconnectDelay = reconnectDelay.Value;

            SetBoolByIndex(bools, 0, v => report.Settings.Install = v);
            SetBoolByIndex(bools, 1, v => report.Settings.Startup = v);
            SetBoolByIndex(bools, 2, v => report.Settings.HideFile = v);
            SetBoolByIndex(bools, 3, v => report.Settings.EnableLogger = v);
            SetBoolByIndex(bools, 4, v => report.Settings.HideLogDirectory = v);
            SetBoolByIndex(bools, 5, v => report.Settings.HideInstallSubDirectory = v);
            SetBoolByIndex(bools, bools.Count - 1, v => report.Settings.UnattendedMode = v);

            report.RecoveryStatus.SettingsClassFound = true;
            report.RecoveryStatus.EncryptionKeyFound = !string.IsNullOrEmpty(report.Settings.EncryptionKey);
            report.RecoveryStatus.HostsFieldFound = !string.IsNullOrEmpty(report.Settings.HostsRaw);
            report.RecoveryStatus.CertificateFieldFound = certField != null;
            report.RecoveryStatus.EncryptedValuesFound = strings.Any(x => LooksLikeBase64(x.Value));
        }

        private static List<StringFieldAssignment> ExtractStaticStringAssignments(TypeDef type)
        {
            List<StringFieldAssignment> result = new List<StringFieldAssignment>();
            MethodDef cctor = type.FindStaticConstructor();

            if (cctor == null || !cctor.HasBody) return result;

            string lastString = null;

            foreach (Instruction ins in cctor.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Ldstr)
                {
                    lastString = ins.Operand as string;
                    continue;
                }

                if (ins.OpCode == OpCodes.Stsfld && lastString != null)
                {
                    IField field = ins.Operand as IField;

                    if (field != null && field.FieldSig != null &&
                        field.FieldSig.Type.FullName == "System.String")
                    {
                        result.Add(new StringFieldAssignment
                        {
                            FieldName = field.Name.String,
                            Value = lastString
                        });
                    }

                    lastString = null;
                }
            }

            return result;
        }

        private static List<BoolFieldAssignment> ExtractStaticBoolAssignments(TypeDef type)
        {
            List<BoolFieldAssignment> result = new List<BoolFieldAssignment>();
            MethodDef cctor = type.FindStaticConstructor();

            if (cctor == null || !cctor.HasBody) return result;

            bool? lastBool = null;

            foreach (Instruction ins in cctor.Body.Instructions)
            {
                if (ins.OpCode == OpCodes.Ldc_I4_0)
                {
                    lastBool = false;
                    continue;
                }

                if (ins.OpCode == OpCodes.Ldc_I4_1)
                {
                    lastBool = true;
                    continue;
                }

                if (ins.OpCode == OpCodes.Stsfld && lastBool.HasValue)
                {
                    IField field = ins.Operand as IField;

                    if (field != null && field.FieldSig != null &&
                        field.FieldSig.Type.FullName == "System.Boolean")
                    {
                        result.Add(new BoolFieldAssignment
                        {
                            FieldName = field.Name.String,
                            Value = lastBool.Value
                        });
                    }

                    lastBool = null;
                }
            }

            return result;
        }

        private static List<IntFieldAssignment> ExtractStaticIntAssignments(TypeDef type)
        {
            List<IntFieldAssignment> result = new List<IntFieldAssignment>();
            MethodDef cctor = type.FindStaticConstructor();

            if (cctor == null || !cctor.HasBody) return result;

            int? lastInt = null;

            foreach (Instruction ins in cctor.Body.Instructions)
            {
                int? value = ReadInlineInt(ins);

                if (value.HasValue)
                {
                    lastInt = value.Value;
                    continue;
                }

                if (ins.OpCode == OpCodes.Stsfld && lastInt.HasValue)
                {
                    IField field = ins.Operand as IField;

                    if (field != null && field.FieldSig != null &&
                        field.FieldSig.Type.FullName == "System.Int32")
                    {
                        result.Add(new IntFieldAssignment
                        {
                            FieldName = field.Name.String,
                            Value = lastInt.Value
                        });
                    }

                    lastInt = null;
                }
            }

            return result;
        }

        private static int? ReadInlineInt(Instruction ins)
        {
            if (ins.OpCode == OpCodes.Ldc_I4_0) return 0;
            if (ins.OpCode == OpCodes.Ldc_I4_1) return 1;
            if (ins.OpCode == OpCodes.Ldc_I4_2) return 2;
            if (ins.OpCode == OpCodes.Ldc_I4_3) return 3;
            if (ins.OpCode == OpCodes.Ldc_I4_4) return 4;
            if (ins.OpCode == OpCodes.Ldc_I4_5) return 5;
            if (ins.OpCode == OpCodes.Ldc_I4_6) return 6;
            if (ins.OpCode == OpCodes.Ldc_I4_7) return 7;
            if (ins.OpCode == OpCodes.Ldc_I4_8) return 8;
            if (ins.OpCode == OpCodes.Ldc_I4_M1) return -1;
            if (ins.OpCode == OpCodes.Ldc_I4_S) return Convert.ToInt32(ins.Operand);
            if (ins.OpCode == OpCodes.Ldc_I4) return Convert.ToInt32(ins.Operand);
            return null;
        }

        private static bool TypeUses(TypeDef type, string text)
        {
            foreach (MethodDef method in type.Methods)
            {
                if (!method.HasBody) continue;

                foreach (Instruction ins in method.Body.Instructions)
                {
                    if (ins.Operand != null && ins.Operand.ToString().Contains(text))
                        return true;
                }
            }

            return false;
        }

        private static bool LooksLikeSha1Hex(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length != 40) return false;

            return value.All(c =>
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F'));
        }

        private static bool LooksLikeBase64(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < 32) return false;

            try
            {
                Convert.FromBase64String(value);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void SetByIndex(List<StringFieldAssignment> list, int index, Action<string> setter)
        {
            if (index >= 0 && index < list.Count)
                setter(list[index].Value);
        }

        private static void SetBoolByIndex(List<BoolFieldAssignment> list, int index, Action<bool?> setter)
        {
            if (index >= 0 && index < list.Count)
                setter(list[index].Value);
        }
    }

    public class QuasarSettingsReport
    {
        public string Project { get; set; }
        public string Mode { get; set; }
        public string AssemblyPath { get; set; }
        public string AssemblyName { get; set; }
        public string EntryPoint { get; set; }
        public string ApplicationType { get; set; }
        public string SettingsType { get; set; }
        public bool SettingsFound { get; set; }

        public QuasarSettings Settings { get; set; } = new QuasarSettings();
        public QuasarRecoveryStatus RecoveryStatus { get; set; } = new QuasarRecoveryStatus();

        public List<StringFieldAssignment> RawStringFields { get; set; } = new List<StringFieldAssignment>();
        public List<BoolFieldAssignment> RawBoolFields { get; set; } = new List<BoolFieldAssignment>();
        public List<IntFieldAssignment> RawIntFields { get; set; } = new List<IntFieldAssignment>();
    }

    public class QuasarSettings
    {
        public string VersionRaw { get; set; }
        public string HostsRaw { get; set; }
        public int? ReconnectDelay { get; set; }
        public string SubDirectoryRaw { get; set; }
        public string InstallNameRaw { get; set; }
        public bool? Install { get; set; }
        public bool? Startup { get; set; }
        public string MutexRaw { get; set; }
        public string StartupKeyRaw { get; set; }
        public bool? HideFile { get; set; }
        public bool? EnableLogger { get; set; }
        public string EncryptionKey { get; set; }
        public string TagRaw { get; set; }
        public string LogDirectoryNameRaw { get; set; }
        public string ServerSignatureRaw { get; set; }
        public string ServerCertificateStrRaw { get; set; }
        public string ServerCertificateField { get; set; }
        public bool? HideLogDirectory { get; set; }
        public bool? HideInstallSubDirectory { get; set; }
        public bool? UnattendedMode { get; set; }

        // NEW
        public string Version { get; set; }
        public string Hosts { get; set; }
        public string SubDirectory { get; set; }
        public string InstallName { get; set; }
        public string Mutex { get; set; }
        public string StartupKey { get; set; }
        public string Tag { get; set; }
        public string LogDirectoryName { get; set; }
    }

    public class QuasarRecoveryStatus
    {
        public bool SettingsClassFound { get; set; }
        public bool HostsFieldFound { get; set; }
        public bool EncryptionKeyFound { get; set; }
        public bool CertificateFieldFound { get; set; }
        public bool EncryptedValuesFound { get; set; }
    }

    public class StringFieldAssignment
    {
        public string FieldName { get; set; }
        public string Value { get; set; }
    }

    public class BoolFieldAssignment
    {
        public string FieldName { get; set; }
        public bool Value { get; set; }
    }

    public class IntFieldAssignment
    {
        public string FieldName { get; set; }
        public int Value { get; set; }
    }
}
