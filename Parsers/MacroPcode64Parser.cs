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
            long offset = reader.BaseStream.Position;

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
                        Offset = offset,
                        Pattern = new System.Collections.Generic.List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACRO_PCODE64 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
