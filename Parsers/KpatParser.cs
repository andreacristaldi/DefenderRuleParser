using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class KpatParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                string hex = BitConverter.ToString(buffer).Replace("-", " ");

                Console.WriteLine($"[KPAT] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hex}");
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_KPAT",
                        Offset = offset,
                        Pattern = new List<string> { hex },
                        Parsed = false 
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] KPAT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
