using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class AaggregatorParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                string hex = BitConverter.ToString(data).Replace("-", " ");

                Console.WriteLine($"[AAGGREGATOR] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hex}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_AAGGREGATOR",
                        Offset = offset,
                        Pattern = new List<string> { hex },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] AAGGREGATOR ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
