using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class PestaticExParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hexLines = new List<string>();

            try
            {
                byte[] data = reader.ReadBytes(size);

                for (int i = 0; i < data.Length; i += 16)
                {
                    string line = $"{(offset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < data.Length)
                            line += $"{data[i + j]:X2} ";
                        else
                            line += "   ";
                    }
                    hexLines.Add(line.TrimEnd());
                }

                Console.WriteLine($"[PESTATICEX] Threat ID: {threatId}, Size {size} bytes");
                Console.WriteLine("  > Hex:\n" + string.Join(Environment.NewLine, hexLines));
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PESTATICEX",
                        Offset = offset,
                        Pattern = hexLines
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] PESTATICEX ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
