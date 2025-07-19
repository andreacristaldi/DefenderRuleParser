using System;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class HstrParser : ISignatureParser
    {
        private const int MaxSubRules = 50;

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;
            try
            {
                byte[] buffer = reader.ReadBytes(size);
                using (MemoryStream ms = new MemoryStream(buffer))
                using (BinaryReader br = new BinaryReader(ms))
                {
                    if (size < 6)
                    {
                        Console.WriteLine($"[HSTR] ⚠ Skipping too small HSTR block at offset 0x{baseOffset:X}");
                        return;
                    }

                    ushort unknown = br.ReadUInt16();
                    int threshold = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                    if (subRuleCount <= 0 || subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[HSTR] ⚠ Invalid subrule count {subRuleCount} for Threat ID {threatId} at 0x{baseOffset:X}");
                        return;
                    }

                    Console.WriteLine($"[HSTR] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        if (br.BaseStream.Position + 3 > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule header #{i + 1} incomplete. Stopping.");
                            break;
                        }

                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();

                        byte optionalCode = 0;
                        if (ms.Position + 1 < ms.Length)
                            optionalCode = br.ReadByte();

                        if (br.BaseStream.Position + subRuleSize > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} exceeds available data. Skipping.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string pattern = ParsePattern(patternBytes);

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={pattern}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_PEHSTR",
                                Offset = baseOffset,
                                Pattern = new System.Collections.Generic.List<string> { pattern }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] HSTR ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
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
                        case 0x01:
                            sb.Append($"[+{val} bytes]");
                            i += 2;
                            continue;
                        case 0x02:
                            sb.Append($"[≤{val} bytes]");
                            i += 2;
                            continue;
                        default:
                            sb.Append('.');
                            break;
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
