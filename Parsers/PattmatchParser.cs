using DefenderRuleParser2;
using DefenderRuleParser2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DefenderRuleParser2.Parsers
{
    public class PattmatchParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                // Best-effort decoding
                string hexDump = BitConverter.ToString(buffer).Replace("-", " ");
                string ascii = ToPrintableAscii(buffer);

                Console.WriteLine($"[PATTERN] Threat ID: {threatId}");
                //Console.WriteLine("  - Hex:   " + Truncate(hexDump, 80));
                Console.WriteLine("  > Hex:   " + hexDump);
                //Console.WriteLine("  - ASCII: " + Truncate(ascii, 80));
                Console.WriteLine("  > ASCII: " + ascii);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PATTMATCH",
                        Offset = offset,
                        Pattern = new List<string> { ascii },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PATTERN] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ToPrintableAscii(byte[] data)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in data)
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            return sb.ToString();
        }

        private string Truncate(string input, int maxLength)
        {
            return string.IsNullOrEmpty(input) ? input :
                   input.Length > maxLength ? input.Substring(0, maxLength) + "..." : input;
        }
    }
}
