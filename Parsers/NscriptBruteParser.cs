using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NscriptBruteParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(buffer).Replace("-", " ");

                Console.WriteLine($"[NSCRIPT_BRUTE] Threat ID: {threatId}, Size: {size} bytes");
                //Console.WriteLine($"  > Hex: {Truncate(hexDump, 80)}");
                Console.WriteLine($"  > Hex: {hexDump}");

                // Add to threat
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NSCRIPT_BRUTE",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NSCRIPT_BRUTE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string Truncate(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input)) return input;
            return input.Length > maxLength ? input.Substring(0, maxLength) + "..." : input;
        }
    }
}
