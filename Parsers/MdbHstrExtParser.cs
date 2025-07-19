using System;
using System.IO;
using System.Text;
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
                using (MemoryStream ms = new MemoryStream(buffer))
                using (BinaryReader br = new BinaryReader(ms))
                {
                    ushort unknown = br.ReadUInt16();
                    int threshold = br.ReadByte() | (br.ReadByte() << 8);
                    int subRuleCount = br.ReadByte() | (br.ReadByte() << 8);

                    if (subRuleCount > MaxSubRules)
                    {
                        Console.WriteLine($"[!] Too many subrules in MDBHSTR_EXT: {subRuleCount}");
                        return;
                    }

                    Console.WriteLine($"[MDBHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();
                        byte optionalCode = 0;

                        if (ms.Position + 1 < ms.Length)
                            optionalCode = br.ReadByte();

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string pattern = ParsePattern(patternBytes);

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={pattern}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_MDBHSTR_EXT",
                                Offset = offset,
                                Pattern = new System.Collections.Generic.List<string> { pattern },
                                Parsed = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MDBHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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
