using DefenderRuleParser2;
using DefenderRuleParser2.Export;
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
                var exportObject = new
                {
                    ThreatName = threat.ThreatName,
                    BeginPosition = threat.BeginPosition,
                    EndPosition = threat.EndPosition,
                    SignatureStats = threat.SignatureStats,
                    Signatures = threat.Signatures

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
    }
}
