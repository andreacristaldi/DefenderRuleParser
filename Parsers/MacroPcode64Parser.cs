using System;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MacroPcode64Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;

            try
            {
                byte[] pcode = reader.ReadBytes(size);

                string hexDump = BitConverter.ToString(pcode).Replace("-", " ");
                Console.WriteLine($"[MACRO_PCODE64] Threat ID: {threatId}, Size: {size} bytes");
                
                Console.WriteLine($"  > Hex: {hexDump}");
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_MACRO_PCODE64",
                        Offset = baseOffset,
                        Pattern = new System.Collections.Generic.List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACRO_PCODE64 ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }
    }
}
