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
                    ushort unknown = br.ReadUInt16();
                    ushort threshold = br.ReadUInt16();
                    ushort subruleCount = br.ReadUInt16();

                    Console.WriteLine($"[DEXHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {subruleCount}");

                    var patterns = new List<string>();

                    for (int i = 0; i < subruleCount && br.BaseStream.Position < br.BaseStream.Length; i++)
                    {
                        ushort weight = br.ReadUInt16();
                        byte ruleSize = br.ReadByte();

                        if (ruleSize == 0 && br.BaseStream.Position < br.BaseStream.Length)
                            ruleSize = br.ReadByte(); // padding fallback

                        if (br.BaseStream.Position + ruleSize > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule {i + 1} truncated.");
                            break;
                        }

                        byte[] patternBytes = br.ReadBytes(ruleSize);
                        string ascii = ToPrintableAscii(patternBytes).Trim();

                        Console.WriteLine($"  > SubRule #{i + 1}: Weight={weight}, Pattern=\"{ascii}\"");

                        patterns.Add(ascii);
                    }

                    if (patterns.Count > 0 && ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_DEXHSTR_EXT",
                            Offset = offset,
                            Pattern = patterns,
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] DEXHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ToPrintableAscii(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (byte b in bytes)
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            return sb.ToString();
        }
    }
}
