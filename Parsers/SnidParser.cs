using System;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class SnidParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;

            try
            {
                byte[] content = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(content).Replace("-", " ");

                Console.WriteLine($"[SNID] Threat ID: {threatId}, Size: {{size}} bytes");                    
                Console.WriteLine("  > Hex:   " + hexDump);
                

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_SNID",
                        Offset = baseOffset,
                        Pattern = new System.Collections.Generic.List<string> { hexDump },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SNID ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }
    }
}
