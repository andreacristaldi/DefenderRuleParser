using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class JavaHstrExtParser : ISignatureParser
    {
        private const int MaxSubRules = 50;

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                var ms = new MemoryStream(buffer);
                var br = new BinaryReader(ms);

                ushort unknown = br.ReadUInt16();
                int threshold = br.ReadByte() | (br.ReadByte() << 8);
                int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                if (subRuleCount <= 0 || subRuleCount > MaxSubRules)
                {
                    Console.WriteLine($"[!] JAVAHSTR_EXT ⚠ Invalid subrule count: {subRuleCount}");
                    return;
                }

                Console.WriteLine($"[JAVAHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                var patterns = new List<string>();

                for (int i = 0; i < subRuleCount; i++)
                {
                    if (ms.Position + 4 > ms.Length)
                    {
                        Console.WriteLine($"  ⚠ SubRule #{i + 1} header truncated.");
                        break;
                    }

                    int weight = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleSize = br.ReadByte();
                    byte optionalCode = br.ReadByte();

                    if (ms.Position + subRuleSize > ms.Length)
                    {
                        Console.WriteLine($"  ⚠ SubRule #{i + 1} body truncated. Skipping.");
                        break;
                    }

                    byte[] patternBytes = br.ReadBytes(subRuleSize);
                    string pattern = ParsePattern(patternBytes);

                    Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={pattern}");
                    patterns.Add(pattern);
                }

                if (patterns.Count > 0 && ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_JAVAHSTR_EXT",
                        Offset = offset,
                        Pattern = patterns,
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] JAVAHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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
