using System;
using System.IO;
using System.Collections.Generic;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class KcrcExParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] rawData = reader.ReadBytes(size);

                if (rawData.Length < 8)
                {
                    Console.WriteLine($"[KCRCEX] ⚠ Too short to parse. Threat ID: {threatId}");
                    return;
                }

                string hexDump = BitConverter.ToString(rawData).Replace("-", " ");
                Console.WriteLine($"[KCRCEX] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hexDump}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_KCRCEX",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[KCRCEX] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
