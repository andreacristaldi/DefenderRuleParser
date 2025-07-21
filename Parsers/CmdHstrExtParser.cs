using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class CmdHstrExtParser : ISignatureParser
    {
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

                    Console.WriteLine($"[CMDHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subRuleCount}");

                    for (int i = 0; i < subRuleCount; i++)
                    {
                        long subStart = br.BaseStream.Position;

                        if (subStart + 4 > ms.Length)
                        {
                            Console.WriteLine($"[CMDHSTR_EXT] ⚠ Incomplete header for SubRule #{i + 1}. Skipping.");
                            break;
                        }

                        int weight = br.ReadByte() | (br.ReadByte() << 8);
                        int subRuleSize = br.ReadByte();
                        byte optionalCode = br.ReadByte(); // may be used for EXT logic

                        if (br.BaseStream.Position + subRuleSize > ms.Length)
                        {
                            Console.WriteLine($"[CMDHSTR_EXT] ⚠ SubRule #{i + 1} truncated. Skipping.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(subRuleSize);
                        string pattern = ParsePattern(patternBytes);

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern={pattern}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_CMDHSTR_EXT",
                                Offset = offset + subStart,
                                Pattern = new List<string> { pattern },
                                Parsed = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] CMDHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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

                    if (type == 0x01)
                    {
                        sb.Append($"[+{val} bytes]");
                        i += 2;
                        continue;
                    }
                    else if (type == 0x02)
                    {
                        sb.Append($"[≤{val} bytes]");
                        i += 2;
                        continue;
                    }
                }

                sb.Append((b >= 32 && b <= 126) ? (char)b : '.');
            }

            return sb.ToString();
        }
    }
}
