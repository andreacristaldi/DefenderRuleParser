using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MdbHstrExtParser : ISignatureParser
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

                ushort _unknown = br.ReadUInt16();
                int threshold = br.ReadByte() | (br.ReadByte() << 8);
                int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                if (subRuleCount > MaxSubRules || subRuleCount <= 0)
                {
                    Console.WriteLine($"[!] MDBHSTR_EXT: Invalid subrule count {subRuleCount}");
                    return;
                }

                Console.WriteLine($"[MDBHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                var patterns = new List<string>();

                for (int i = 0; i < subRuleCount; i++)
                {
                    if (br.BaseStream.Position + 3 > br.BaseStream.Length)
                    {
                        Console.WriteLine($"  ⚠ SubRule #{i + 1} header truncated.");
                        break;
                    }

                    int weight = br.ReadByte() | (br.ReadByte() << 8);
                    int ruleSize = br.ReadByte();
                    byte optionalCode = (ms.Position + 1 < ms.Length) ? br.ReadByte() : (byte)0;

                    if (br.BaseStream.Position + ruleSize > br.BaseStream.Length)
                    {
                        Console.WriteLine($"  ⚠ SubRule #{i + 1} data truncated.");
                        break;
                    }

                    byte[] patternBytes = br.ReadBytes(ruleSize);
                    string pattern = ParsePattern(patternBytes);

                    Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={Truncate(pattern, 80)}");

                    patterns.Add(pattern);
                }

                if (patterns.Count > 0 && ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_MDBHSTR_EXT",
                        Offset = offset,
                        Pattern = patterns,
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MDBHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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

            return sb.ToString().Trim('\0');
        }

        private string Truncate(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input)) return input;
            return input.Length > maxLength ? input.Substring(0, maxLength) + "..." : input;
        }
    }
}

