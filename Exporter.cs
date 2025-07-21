using DefenderRuleParser2;
using DefenderRuleParser2.Export;
using DefenderRuleParser2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace DefenderRuleParser2
{
    public static class Exporter
    {
        public static void SaveAllThreats(string outputFolder, string name)
        {
            if (!Directory.Exists(outputFolder))
            {
                Directory.CreateDirectory(outputFolder);
            }

            List<object> exportList = new List<object>();

            foreach (Threat threat in ThreatDatabase.GetAllThreats())
            {
                var cleanedSignatures = threat.Signatures.Select(sig => new
                {
                    Type = sig.Type,
                    Offset = sig.Offset,
                    Parsed = sig.Parsed,
                    Pattern = sig.Pattern?.Select(CleanPatternLine).Where(p => !string.IsNullOrWhiteSpace(p)).ToList()
                });

                var exportObject = new
                {
                    ThreatName = threat.ThreatName,
                    BeginPosition = threat.BeginPosition,
                    EndPosition = threat.EndPosition,
                    SignatureStats = threat.SignatureStats,
                    Signatures = cleanedSignatures
                };

                exportList.Add(exportObject);
            }

            JavaScriptSerializer serializer = new JavaScriptSerializer
            {
                MaxJsonLength = int.MaxValue
            };

            string jsonOutput = serializer.Serialize(exportList);
            string outputPath = Path.Combine(outputFolder, name + ".json");
            File.WriteAllText(outputPath, jsonOutput);

            

            HtmlExporter.ExportThreatsAsHtml(ThreatDatabase.GetAllThreats().ToList(), Path.Combine(outputFolder, name + ".html"));
            YaraExporter.ExportThreatsAsYara(ThreatDatabase.GetAllThreats().ToList(), Path.Combine(outputFolder, name + ".yar"));
            Console.WriteLine("[✓] Exported all threats to: " + outputPath);
        }

        private static string CleanPatternLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;

            // Esempio: "0040AB12 90 90 90" => "90 90 90"
            if (line.Length >= 9 && IsHexOffset(line.Substring(0, 8)) && line[8] == ' ')
            {
                return line.Substring(9).Trim();
            }

            return line.Trim();
        }

        private static bool IsHexOffset(string s)
        {
            return s.Length == 8 && s.All(c => Uri.IsHexDigit(c));
        }
    }
}
