using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class CkSimpleRecParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                var bytes = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(bytes).Replace("-", " ");

                Console.WriteLine($"[CKSIMPLEREC] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hexDump}");
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_CKSIMPLEREC",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] CKSIMPLEREC ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin); // fallback per evitare blocchi
            }
        }
    }
}
