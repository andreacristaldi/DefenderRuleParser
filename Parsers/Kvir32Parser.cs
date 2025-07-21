using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class Kvir32Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {

                byte[] data = reader.ReadBytes(size);
                List<string> formatted = new List<string>();

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
                    formatted.Add(line.TrimEnd());
                }

                Console.WriteLine($"[KVIR32] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Dump:\n" + string.Join(Environment.NewLine, formatted));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_KVIR32",
                        Offset = offset,
                        Pattern = formatted,
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] KVIR32 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
