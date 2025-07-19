using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class DexHstrExtParser : ISignatureParser
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
                    ushort unknown = br.ReadUInt16(); // di solito non rilevante
                    ushort threshold = br.ReadUInt16(); // soglia HSTR
                    ushort subruleCount = br.ReadUInt16();

                    Console.WriteLine($"[DEXHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subruleCount}");

                    for (int i = 0; i < subruleCount && br.BaseStream.Position < br.BaseStream.Length; i++)
                    {
                        ushort weight = br.ReadUInt16();
                        byte ruleSize = br.ReadByte();

                        if (ruleSize == 0 && br.BaseStream.Position < br.BaseStream.Length)
                            ruleSize = br.ReadByte(); // padding

                        if (br.BaseStream.Position + ruleSize > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule {i + 1} truncated.");
                            break;
                        }

                        byte[] pattern = br.ReadBytes(ruleSize);
                        string decoded = Encoding.UTF8.GetString(pattern).Trim('\0');

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern=\"{decoded}\"");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_DEXHSTR_EXT",
                                Offset = offset,
                                Pattern = new List<string> { decoded }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] DEXHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(size, SeekOrigin.Current);
            }
        }
    }
}
