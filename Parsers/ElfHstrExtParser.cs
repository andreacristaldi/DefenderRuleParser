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
                    // Header (magic, padding, threshold, reserved, rule count)
                    ushort magic = br.ReadUInt16();
                    ushort padding = br.ReadUInt16();
                    ushort threshold = br.ReadUInt16();
                    ushort reserved = br.ReadUInt16();
                    ushort ruleCount = br.ReadUInt16();

                    Console.WriteLine($"[ELFHSTR_EXT] Threat ID: {threatId}, Threshold: {threshold}, SubRules: {ruleCount}");

                    var patterns = new List<string>();

                    for (int i = 0; i < ruleCount && br.BaseStream.Position + 3 <= br.BaseStream.Length; i++)
                    {
                        byte unknown1 = br.ReadByte();
                        ushort len = br.ReadUInt16();

                        if (br.BaseStream.Position + len > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ SubRule #{i + 1} truncated. Skipping.");
                            break;
                        }

                        byte[] data = br.ReadBytes(len);
                        string pattern = ToPrintableAscii(data).Trim();

                        Console.WriteLine($"  > SubRule #{i + 1}: Pattern=\"{pattern}\"");
                        patterns.Add(pattern);
                    }

                    if (patterns.Count > 0 && ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_ELFHSTR_EXT",
                            Offset = offset,
                            Pattern = patterns,
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ELFHSTR_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ToPrintableAscii(byte[] data)
        {
            var sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }
            return sb.ToString();
        }
    }
}
