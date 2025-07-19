using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Export
{
    public class YaraExporter
    {
        public static void ExportThreatsAsYara(List<Threat> threats, string outputFolder)
        {
            foreach (var threat in threats)
            {
                var yara = new StringBuilder();

                string ruleName = SanitizeRuleName(threat.ThreatName);
                yara.AppendLine($"rule {ruleName}");
                yara.AppendLine("{");
                yara.AppendLine("    meta:");
                yara.AppendLine($"        threat_name = \"{threat.ThreatName}\"");
                yara.AppendLine($"        offset_start = \"0x{threat.BeginPosition:X}\"");
                yara.AppendLine($"        offset_end = \"0x{threat.EndPosition:X}\"");

                var stringCounter = 0;
                yara.AppendLine("    strings:");

                var conditions = new List<string>();

                foreach (var sig in threat.Signatures.Where(s => s.Pattern != null && s.Pattern.Any()))
                {
                    foreach (var pattern in sig.Pattern)
                    {
                        string varName = $"$a{stringCounter}";
                        string hex = ConvertToHexIfNeeded(pattern);
                        yara.AppendLine($"        {varName} = {{ {hex} }} // {sig.Type}");
                        conditions.Add(varName);
                        stringCounter++;
                    }
                }

                yara.AppendLine("    condition:");
                yara.AppendLine("        " + (conditions.Count > 0 ? string.Join(" or ", conditions) : "false"));
                yara.AppendLine("}");

                
                File.WriteAllText(outputFolder, yara.ToString(), Encoding.UTF8);
            }
        }

        private static string SanitizeRuleName(string name)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            return new string(name.Where(c => !invalidChars.Contains(c)).ToArray())
                .Replace(" ", "_")
                .Replace(":", "_")
                .Replace("/", "_");
        }

        private static string ConvertToHexIfNeeded(string input)
        {
            if (input.All(c => Uri.IsHexDigit(c) || c == ' ')) return input;

            var bytes = Encoding.ASCII.GetBytes(input);
            return string.Join(" ", bytes.Select(b => b.ToString("X2")));
        }
    }
}
