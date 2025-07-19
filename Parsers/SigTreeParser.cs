using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class SigtreeParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;
            var hexDump = new List<string>();

            try
            {
                byte[] data = reader.ReadBytes(size);

                for (int i = 0; i < data.Length; i += 16)
                {
                    var line = $"{(baseOffset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < data.Length)
                            line += $"{data[i + j]:X2} ";
                        else
                            line += "   ";
                    }

                    hexDump.Add(line.TrimEnd());
                }

                Console.WriteLine($"[SIGTREE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex:\n" + string.Join(Environment.NewLine, hexDump));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_SIGTREE",
                        Offset = baseOffset,
                        Pattern = hexDump
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SIGTREE ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }
    }
}
