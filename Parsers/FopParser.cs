using System;
using System.IO;
using System.Collections.Generic;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class FopParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] bytes = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(bytes).Replace("-", " ");

                Console.WriteLine($"[FOP] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex:   {hexDump}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_FOP",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FOP] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
