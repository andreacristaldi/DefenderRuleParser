using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NscriptSpParser : ISignatureParser
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
                    Console.WriteLine($"[NSCRIPT_SP] Threat ID: {threatId}, Size: {size} bytes");

                    // Heuristic parsing: search for strings (if any)
                    List<string> strings = new List<string>();
                    var sb = new StringBuilder();

                    while (br.BaseStream.Position < br.BaseStream.Length)
                    {
                        byte b = br.ReadByte();
                        if (b >= 32 && b <= 126)
                        {
                            sb.Append((char)b);
                        }
                        else
                        {
                            if (sb.Length >= 4)
                            {
                                strings.Add(sb.ToString());
                            }
                            sb.Clear();
                        }
                    }
                    if (sb.Length >= 4)
                    {
                        strings.Add(sb.ToString());
                    }

                    foreach (var str in strings)
                    {
                        Console.WriteLine($"  > Found string: \"{str}\"");
                    }

                    if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_NSCRIPT_SP",
                            Offset = offset,
                            Pattern = strings,
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NSCRIPT_SP ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
