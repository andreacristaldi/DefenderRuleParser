using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Export
{
    public class HtmlExporter
    {
        private static readonly Dictionary<string, string> SignatureDescriptions = new Dictionary<string, string>
        {
            { "SIGNATURE_TYPE_PEHSTR", "PEHSTR-based signature likely refers to PE header string pattern matching." },
            { "SIGNATURE_TYPE_PEHSTR_EXT", "Extended PEHSTR rule for additional matching conditions." },
            { "SIGNATURE_TYPE_PEHSTR_EXT2", "Second level of extended PEHSTR signature rules." },
            { "SIGNATURE_TYPE_REGKEY", "Detects presence of suspicious or malicious registry keys." },
            { "SIGNATURE_TYPE_FILEPATH", "Triggers on specific file paths indicative of threats." },
            { "SIGNATURE_TYPE_FILENAME", "Triggers on specific suspicious file names." },
            { "SIGNATURE_TYPE_FOLDERNAME", "Triggers on folder names commonly used by malware." },
            { "SIGNATURE_TYPE_STATIC", "Generic static data or hash check, commonly short sequences or static patterns." },
            { "SIGNATURE_TYPE_KVIR32", "Pattern linked to KVIR-style 32-bit malware behavior." },
            { "SIGNATURE_TYPE_LUASTANDALONE", "Includes a standalone embedded Lua script for behavioral evaluation." },
            { "SIGNATURE_TYPE_PATTMATCH", "Hex or byte sequence match, commonly found in packed payloads." },
            { "SIGNATURE_TYPE_PATTMATCH_V2", "An evolved variant of PATTMATCH supporting more complex sequences." },
            { "SIGNATURE_TYPE_LOCALHASH", "Checks for local hash presence or match in Defender's database." },
            { "SIGNATURE_TYPE_SIGTREE", "Signature tree structure possibly used for decision chaining." },
            { "SIGNATURE_TYPE_SIGTREE_EXT", "Extended signature tree structure for hierarchical evaluation." },
            { "SIGNATURE_TYPE_PEPCODE", "Pattern in the PE code section indicative of malware logic." },
            { "SIGNATURE_TYPE_CKSIMPLEREC", "Checksum-based detection using a simplified record structure." },
            { "SIGNATURE_TYPE_KCRCE", "Kernel-based CRC checks possibly verifying integrity of code blocks." },
            { "SIGNATURE_TYPE_KCRCEX", "Extended version of the kernel CRC integrity verification." },
            { "SIGNATURE_TYPE_MACRO_PCODE", "Traces of suspicious Office macro p-code (binary form)." },
            { "SIGNATURE_TYPE_MACRO_SOURCE", "Detects text-based macro source code patterns." },
            { "SIGNATURE_TYPE_MACRO_PCODE64", "64-bit p-code variants of Office macros." },
            { "SIGNATURE_TYPE_NSCRIPT_CURE", "Cure logic applied via Defender's native script engine." },
            { "SIGNATURE_TYPE_NID", "Named Identifier – a label used internally to tag detections." },
            { "SIGNATURE_TYPE_ELFHSTR_EXT", "HSTR-style rule targeting ELF binaries, commonly used in Linux detections." },
            { "SIGNATURE_TYPE_DEXHSTR_EXT", "HSTR signature for Android DEX files (Dalvik executables)." },
            { "SIGNATURE_TYPE_INNOHSTR_EXT", "HSTR match within Inno Setup installers, commonly abused by malware." },
            { "SIGNATURE_TYPE_CMDHSTR_EXT", "Command-line based behavior pattern recognition." },
            { "SIGNATURE_TYPE_THREAD_X86", "Indicates X86-specific thread-level behavior matching." },
            { "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE", "Targets compiled scripts, such as VBScript or JScript bytecode." },
            { "SIGNATURE_TYPE_UFSP_DISABLE", "Detects attempt to disable Defender's User-Mode File System Protection (UFSP)." },
            { "SIGNATURE_TYPE_DEFAULTS", "Presence of known default configurations often changed by malware." },
            { "SIGNATURE_TYPE_BOOT", "Detection patterns aimed at boot sector threats or modifications." }
        };

        public static void ExportThreatsAsHtml(List<Threat> threats, string outputPath)
        {
            var html = new StringBuilder();

            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html lang=\"en\">");
            html.AppendLine("<head>");
            html.AppendLine("    <meta charset=\"UTF-8\">");
            html.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            html.AppendLine("    <title>DefenderRuleParser Report</title>");
            html.AppendLine("    <style>");
            html.AppendLine("        body { font-family: Arial, sans-serif; margin: 2em; background: #f5f5f5; }");
            html.AppendLine("        .threat-block { background: #fff; padding: 1em; margin-bottom: 1.5em; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }");
            html.AppendLine("        .threat-name { font-size: 1.4em; font-weight: bold; color: #2c3e50; }");
            html.AppendLine("        .signature { margin-left: 1em; padding: 0.5em; border-left: 3px solid #3498db; background: #eef6fb; margin-top: 0.5em; }");
            html.AppendLine("        .sig-type { font-weight: bold; color: #2980b9; }");
            html.AppendLine("        .sig-pattern { font-family: monospace; color: #555; }");
            html.AppendLine("        .sig-description { font-style: italic; font-size: 0.9em; margin-top: 0.3em; color: #666; }");
            html.AppendLine("    </style>");
            html.AppendLine("</head>");
            html.AppendLine("<body>");

            html.AppendLine("<h1>DefenderRuleParser Report</h1>");
            html.AppendLine("<p>This report presents the extracted detection logic from Microsoft Defender signature rules.</p>");
            html.AppendLine("<p>Project: Andrea Cristaldi <a href=\"https://github.com/andreacristaldi/DefenderRuleParser\" target=\"blank_\">Github project</a>, <a href=\"https://www.linkedin.com/in/andreacristaldi/\" target=\"blank_\">Linkedin</a>.</p>");

            foreach (var threat in threats)
            {
                html.AppendLine("<div class=\"threat-block\">");
                html.AppendLine($"<div class='threat-name'>{threat.ThreatName}</div>");
                html.AppendLine($"<p><strong>Offset Range:</strong> 0x{threat.BeginPosition:X} - 0x{threat.EndPosition:X}</p>");
                html.AppendLine("<div><strong>Detected Signatures:</strong>");

                foreach (var sig in threat.Signatures)
                {
                    html.AppendLine("<div class='signature'>");
                    html.AppendLine($"<div class='sig-type'>{sig.Type}</div>");

                    if (SignatureDescriptions.TryGetValue(sig.Type, out var desc))
                    {
                        html.AppendLine($"<div class='sig-description'>{desc}</div>");
                    }

                    if (sig.Pattern != null && sig.Pattern.Any())
                    {
                        // Ricostruisci offset solo per alcuni tipi noti
                        var isHexDump = ShouldReformatWithOffset(sig.Type);
                        if (isHexDump)
                        {
                            long offset = sig.Offset;
                            int rowSize = 16;

                            var bytes = sig.Pattern
                                .SelectMany(p => p.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                                .Where(x => x.Length == 2 && Uri.IsHexDigit(x[0]) && Uri.IsHexDigit(x[1]))
                                .ToList();

                            for (int i = 0; i < bytes.Count; i += rowSize)
                            {
                                var chunk = bytes.Skip(i).Take(rowSize).ToList();
                                string hex = string.Join(" ", chunk);
                                string addr = (offset + i).ToString("X8");
                                html.AppendLine($"<div class='sig-pattern'>{addr} {System.Net.WebUtility.HtmlEncode(hex)}</div>");
                            }
                        }
                        else
                        {
                            foreach (var pat in sig.Pattern)
                            {
                                html.AppendLine($"<div class='sig-pattern'>{System.Net.WebUtility.HtmlEncode(pat)}</div>");
                            }
                        }
                    }


                    html.AppendLine("</div>");
                }

                html.AppendLine("</div>");
                html.AppendLine("</div>");
            }

            html.AppendLine("</body>");
            html.AppendLine("</html>");

            File.WriteAllText(outputPath, html.ToString(), Encoding.UTF8);
        }

        private static bool ShouldReformatWithOffset(string type)
        {
            // Signature types per cui ha senso reinserire offset esadecimali
            var typesWithHexDump = new HashSet<string>
                    {
                        "SIGNATURE_TYPE_STATIC",
                        "SIGNATURE_TYPE_PEPCODE",
                        "SIGNATURE_TYPE_PESTATIC",
                        "SIGNATURE_TYPE_PESTATICEX",
                        "SIGNATURE_TYPE_THREAD_X86",
                        "SIGNATURE_TYPE_KCRCE",
                        "SIGNATURE_TYPE_KCRCEX",
                        "SIGNATURE_TYPE_KPATEX",
                        "SIGNATURE_TYPE_NID"
                    };

            return typesWithHexDump.Contains(type);
        }

    }
}
