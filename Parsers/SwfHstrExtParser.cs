using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class SwfHstrExtParser : ISignatureParser
    {
        private const int MaxSubRules = 50;

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                using (MemoryStream ms = new MemoryStream(buffer))
                using (BinaryReader br = new BinaryReader(ms))
                {
                    ushort unknown = br.ReadUInt16();
                    int threshold = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                    if (subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[!] SWFHSTR_EXT subrule count too high: {subRuleCount}");
                        return;
                    }

                    Console.WriteLine($"[SWFHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        if (ms.Position + 3 > ms.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule header truncated at #{i + 1}");
                            break;
                        }

                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();

                        byte optionalCode = 0;
                        if (ms.Position + 1 < ms.Length)
                            optionalCode = br.ReadByte();

                        if (ms.Position + subRuleSize > ms.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} truncated, skipping.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string pattern = ParsePattern(patternBytes);

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={Truncate(pattern, 80)}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_SWFHSTR_EXT",
                                Offset = offset,
                                Pattern = new List<string> { pattern },
                                Parsed = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SWFHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ParsePattern(byte[] bytes)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];

                if (b == 0x90 && i + 2 < bytes.Length)
                {
                    byte type = bytes[i + 1];
                    byte val = bytes[i + 2];

                    switch (type)
                    {
                        case 0x01: sb.Append($"[+{val} bytes]"); i += 2; continue;
                        case 0x02: sb.Append($"[≤{val} bytes]"); i += 2; continue;
                        default: sb.Append('.'); break;
                    }
                }
                else if (b >= 32 && b <= 126)
                {
                    sb.Append((char)b);
                }
                else
                {
                    sb.Append('.');
                }
            }

            return sb.ToString();
        }

        private string Truncate(string input, int maxLength)
        {
            return string.IsNullOrEmpty(input) ? input :
                (input.Length > maxLength ? input.Substring(0, maxLength) + "..." : input);
        }
    }
}

