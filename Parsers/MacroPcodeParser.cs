using System;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MacroPcodeParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] rawData = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(rawData).Replace("-", " ");

                Console.WriteLine($"[MACRO_PCODE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Hex: {hexDump}");
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_MACRO_PCODE",
                        Offset = offset,
                        Pattern = new System.Collections.Generic.List<string> { hexDump },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACRO_PCODE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
