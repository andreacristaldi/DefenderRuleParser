using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MachOHstrExtParser : ISignatureParser
    {
        private const int MaxSubRules = 50;

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;
            byte[] buffer = reader.ReadBytes(size);

            try
            {
                using (MemoryStream ms = new MemoryStream(buffer))
                using (BinaryReader br = new BinaryReader(ms))
                {
                    if (buffer.Length < 6)
                    {
                        Console.WriteLine($"[MACHOHSTR_EXT] ⚠ Too short to parse. Threat ID: {threatId}");
                        return;
                    }

                    ushort unknown = br.ReadUInt16();
                    int threshold = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                    Console.WriteLine($"[MACHOHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    if (subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[!] SubRule count too high: {subRuleCount}, aborting parse.");
                        return;
                    }

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        if (ms.Position + 4 > ms.Length)
                        {
                            Console.WriteLine($"[!] SubRule #{i + 1} truncated (not enough bytes).");
                            break;
                        }

                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();
                        byte code = br.ReadByte(); // marker / metadata

                        if (ms.Position + subRuleSize > ms.Length)
                        {
                            Console.WriteLine($"  ⛔ SubRule #{i + 1}: pattern size exceeds available data.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string pattern = ParsePattern(patternBytes);

                        Console.WriteLine($"  ➤ SubRule #{i + 1}: Weight={weight}, Pattern={Truncate(pattern, 80)}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_MACHOHSTR_EXT",
                                Offset = baseOffset,
                                Pattern = new List<string> { pattern }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACHOHSTR_EXT ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
            }
            finally
            {
                // Always skip to the next signature block
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }

        private string ParsePattern(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var b in bytes)
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            return sb.ToString();
        }

        private string Truncate(string input, int maxLen)
        {
            return input.Length > maxLen ? input.Substring(0, maxLen) + "..." : input;
        }
    }
}
