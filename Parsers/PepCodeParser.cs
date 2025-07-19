using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class PepCodeParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var lines = new List<string>();

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string hexLine = $"{(offset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < buffer.Length)
                            hexLine += $"{buffer[i + j]:X2} ";
                        else
                            hexLine += "   ";
                    }
                    lines.Add(hexLine.TrimEnd());
                }

                Console.WriteLine($"[PEPCODE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Lines: " + lines);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PEPCODE",
                        Offset = offset,
                        Pattern = lines
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] PEPCODE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
