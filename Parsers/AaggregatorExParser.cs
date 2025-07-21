using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class AaggregatorExParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                string hex = BitConverter.ToString(data).Replace("-", " ").Trim();

                Console.WriteLine($"[AAGGREGATOREX] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hex}");

                if (!string.IsNullOrEmpty(hex) && ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_AAGGREGATOREX",
                        Offset = offset,
                        Pattern = new List<string> { hex },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] AAGGREGATOREX ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {
                
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

