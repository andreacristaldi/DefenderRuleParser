using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MacroHstrExtParser : ISignatureParser
    {
        private const int MaxSubRules = 100;

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            try
            {
                byte[] buffer = reader.ReadBytes(size);
                using (var ms = new MemoryStream(buffer))
                using (var br = new BinaryReader(ms))
                {
                    ushort unknown = br.ReadUInt16();
                    int threshold = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                    if (subRuleCount <= 0 || subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[MACROHSTR_EXT] ⚠ Invalid subrule count: {subRuleCount}");
                        return;
                    }

                    Console.WriteLine($"[MACROHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    var patterns = new List<string>();

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        if (ms.Position + 4 > ms.Length)
                        {
                            Console.WriteLine($"[MACROHSTR_EXT] ⚠ Incomplete subrule header at #{i + 1}");
                            break;
                        }

                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int ruleSize = br.ReadByte();
                        byte optionalCode = br.ReadByte(); // may be unused

                        if (ms.Position + ruleSize > ms.Length)
                        {
                            Console.WriteLine($"[MACROHSTR_EXT] ⚠ Subrule #{i + 1} truncated. Skipping.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(ruleSize);
                        string decoded = ParsePattern(patternBytes);
                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={decoded}");
                        patterns.Add(decoded);
                    }

                    if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_MACROHSTR_EXT",
                            Offset = offset,
                            Pattern = patterns
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACROHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ParsePattern(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (byte b in bytes)
                sb.Append((b >= 32 && b <= 126) ? (char)b : '.');
            return sb.ToString();
        }
    }
}
