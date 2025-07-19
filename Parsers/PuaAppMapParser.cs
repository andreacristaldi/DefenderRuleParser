using System;
using System.IO;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class PuaAppMapParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] rawData = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(rawData).Replace("-", " ");

                Console.WriteLine($"[PUA_APPMAP] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex:   " + hexDump);
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PUA_APPMAP",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PUA_APPMAP] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
