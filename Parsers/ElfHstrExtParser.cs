using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class ElfHstrExtParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            try
            {
                byte[] buffer = reader.ReadBytes(size);
                using (var ms = new MemoryStream(buffer))
                using (var br = new BinaryReader(ms))
                {
                    // Skip header (e.g., 2 bytes unknown + optional)
                    ushort magic = br.ReadUInt16();
                    ushort padding = br.ReadUInt16(); // usually zero

                    ushort threshold = br.ReadUInt16();
                    ushort _ = br.ReadUInt16(); // reserved/unknown
                    ushort ruleCount = br.ReadUInt16();

                    Console.WriteLine($"[ELFHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {ruleCount}");

                    for (int i = 0; i < ruleCount; i++)
                    {
                        if (br.BaseStream.Position + 3 > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} incomplete or truncated");
                            break;
                        }

                        byte unknown1 = br.ReadByte(); // type/flag?
                        ushort len = br.ReadUInt16();

                        if (br.BaseStream.Position + len > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} out of bounds (len={len})");
                            break;
                        }

                        byte[] data = br.ReadBytes(len);
                        string pattern = Encoding.UTF8.GetString(data).Trim('\0');

                        Console.WriteLine($"  > SubRule #{i + 1}: Pattern=\"{pattern}\"");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_ELFHSTR_EXT",
                                Offset = offset,
                                Pattern = new List<string> { pattern }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ELFHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(size, SeekOrigin.Current);
            }
        }
    }
}
