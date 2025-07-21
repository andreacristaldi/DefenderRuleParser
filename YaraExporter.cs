using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Export
{
    public class YaraExporter
    {
        public static void ExportThreatsAsYara(List<Threat> threats, string outputPath)
        {
            var sb = new StringBuilder();

            foreach (var threat in threats)
            {
                string ruleName = SanitizeRuleName(threat.ThreatName);

                sb.AppendLine($"rule {ruleName}");
                sb.AppendLine("{");
                sb.AppendLine("    meta:");
                sb.AppendLine($"        threat_name = \"{threat.ThreatName}\"");
                sb.AppendLine($"        offset_start = \"0x{threat.BeginPosition:X}\"");
                sb.AppendLine($"        offset_end = \"0x{threat.EndPosition:X}\"");
                sb.AppendLine($"        project = \"DefenderRuleParser on GitHub\"");
                sb.AppendLine($"        author = \"Andrea Cristaldi\"");

                int stringId = 0;
                var conditions = new List<string>();

                sb.AppendLine("    strings:");

                foreach (var sig in threat.Signatures.Where(s => s.Pattern != null && s.Pattern.Any()))
                {
                    var normalizedHex = NormalizePattern(sig.Pattern);
                    if (string.IsNullOrEmpty(normalizedHex)) continue;

                    string varName = $"$a{stringId++}";
                    sb.AppendLine($"        {varName} = {{ {normalizedHex} }} // {sig.Type}");
                    conditions.Add(varName);
                }

                sb.AppendLine("    condition:");
                sb.AppendLine("        " + (conditions.Count > 0 ? string.Join(" or ", conditions) : "false"));
                sb.AppendLine("}");
                sb.AppendLine();
            }

            File.WriteAllText(outputPath, sb.ToString(), Encoding.UTF8);
        }

        private static string SanitizeRuleName(string name)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            return new string(name.Where(c => !invalidChars.Contains(c)).ToArray())
                .Replace(" ", "_")
                .Replace(":", "_")
                .Replace("/", "_");
        }

        private static string NormalizePattern(List<string> lines)
        {
            var hexBytes = new List<string>();

            foreach (var line in lines)
            {
                // Se esiste un indirizzo a sinistra (8 cifre hex), rimuovilo
                string clean = line.Trim();
                if (clean.Length >= 9 && IsHexAddress(clean.Substring(0, 8)))
                    clean = clean.Substring(9);

                var parts = clean.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                if (parts.All(p => p.Length == 2 && IsHex(p)))
                {
                    hexBytes.AddRange(parts);
                }
                else
                {
                    // pattern non valido per YARA come hex, ignoriamo
                    return null;
                }
            }

            return string.Join(" ", hexBytes);
        }

        private static bool IsHex(string s)
        {
            return s.All(c => Uri.IsHexDigit(c));
        }

        private static bool IsHexAddress(string s)
        {
            return s.Length == 8 && s.All(c => Uri.IsHexDigit(c));
        }
    }
}

