using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class KcrceParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hex = new List<string>();

            try
            {
                byte[] data = reader.ReadBytes(size);

                for (int i = 0; i < data.Length; i += 16)
                {
                    var line = $"{(offset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < data.Length)
                            line += $"{data[i + j]:X2} ";
                        else
                            line += "   ";
                    }
                    hex.Add(line.TrimEnd());
                }

                Console.WriteLine($"[KCRCE] Threat ID: {threatId}, Size {size} bytes");
                Console.WriteLine("  > Hex:\n" + string.Join(Environment.NewLine, hex));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_KCRCE",
                        Offset = offset,
                        Pattern = hex
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] KCRCE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

