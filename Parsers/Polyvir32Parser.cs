using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class Polyvir32Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] bytes = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(bytes).Replace("-", " ");

                Console.WriteLine($"[POLYVIR32] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex: " + hexDump);
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_POLYVIR32",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] POLYVIR32 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
