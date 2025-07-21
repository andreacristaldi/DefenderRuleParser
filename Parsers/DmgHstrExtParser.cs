using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class DmgHstrExtParser : ISignatureParser
    {
        private const int MaxSubRules = 50;

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

                    if (subRuleCount < 0 || subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[DMGHSTR_EXT] ⚠ Invalid subrule count: {subRuleCount}");
                        return;
                    }

                    Console.WriteLine($"[DMGHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    var patterns = new List<string>();

                    for (int i = 0; i < subRuleCount && br.BaseStream.Position < br.BaseStream.Length; i++)
                    {
                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();

                        byte optionalCode = 0;
                        if (br.BaseStream.Position + 1 < br.BaseStream.Length)
                            optionalCode = br.ReadByte();

                        if (br.BaseStream.Position + subRuleSize > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} truncated or invalid size. Skipping.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string decoded = ParsePattern(patternBytes);

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={decoded}");
                        patterns.Add(decoded);
                    }

                    if (patterns.Count > 0 && ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_DMGHSTR_EXT",
                            Offset = offset,
                            Pattern = patterns,
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] DMGHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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
    }
}
