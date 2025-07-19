using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;

namespace DefenderRuleParser2
{
    public static class ThreatDatabase
    {
        private static readonly Dictionary<uint, Threat> Threats = new Dictionary<uint, Threat>();
        private static readonly Dictionary<string, string> ThreatIdToName = new Dictionary<string, string>();

        public static void Load(string csvPath)
        {
            if (!File.Exists(csvPath))
            {
                Console.WriteLine("[!] CSV file not found: " + csvPath);
                return;
            }

            string[] lines = File.ReadAllLines(csvPath);

            for (int i = 1; i < lines.Length; i++)
            {
                string[] fields = SplitCsvLine(lines[i]);

                if (fields.Length >= 4)
                {
                    string threatId = fields[2];
                    string threatName = fields[3];

                    if (!ThreatIdToName.ContainsKey(threatId))
                    {
                        ThreatIdToName.Add(threatId, threatName);
                    }
                }
            }

            Console.WriteLine("[✓] Loaded " + ThreatIdToName.Count + " threat names from CSV.");
        }

        public static Threat CreateOrUpdateThreat(uint threatId, long beginPosition)
        {
            Threat threat;
            if (!Threats.TryGetValue(threatId, out threat))
            {
                string name;
                if (!ThreatIdToName.TryGetValue(threatId.ToString(), out name))
                {
                    name = "Unknown";
                }

                threat = new Threat
                {
                    ThreatName = name,
                    BeginPosition = beginPosition
                };

                Threats[threatId] = threat;
            }

            return threat;
        }

        public static bool TryUpdateThreatEnd(uint threatId, long endPosition)
        {
            Threat threat;
            if (Threats.TryGetValue(threatId, out threat))
            {
                if (threat.EndPosition == 0)
                {
                    threat.EndPosition = endPosition;
                    return true;
                }
            }

            return false;
        }

        public static IEnumerable<Threat> GetAllThreats()
        {
            return Threats.Values;
        }

        private static string[] SplitCsvLine(string line)
        {
            List<string> result = new List<string>();
            bool inQuotes = false;
            string currentField = "";

            foreach (char c in line)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ',' && !inQuotes)
                {
                    result.Add(currentField);
                    currentField = "";
                }
                else
                {
                    currentField += c;
                }
            }

            result.Add(currentField);
            return result.ToArray();
        }

        public static void AddThreat(uint id, Threat threat)
        {
            if (!Threats.ContainsKey(id))
            {
                Threats.Add(id, threat);
            }
        }

        public static bool TryGetThreat(uint id, out Threat threat)
        {
            return Threats.TryGetValue(id, out threat);
        }

        public static IEnumerable<Threat> GetAll()
        {
            return Threats.Values;
        }

        public static void Clear()
        {
            Threats.Clear();
        }
    }
}
