using System;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NscriptCureParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(buffer).Replace("-", " ");

                // Tentiamo di estrarre anche stringhe leggibili
                string asciiPreview = Encoding.ASCII.GetString(buffer);
                string filtered = ExtractAsciiStrings(asciiPreview, minLen: 4);

                Console.WriteLine($"[NSCRIPT_CURE] Threat ID: {threatId}, Size: {size} bytes");
                if (!string.IsNullOrWhiteSpace(filtered))
                    Console.WriteLine($"> Embedded text: {filtered}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NSCRIPT_CURE",
                        Offset = baseOffset,
                        Pattern = new System.Collections.Generic.List<string> { filtered, hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NSCRIPT_CURE ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }

        private string ExtractAsciiStrings(string input, int minLen = 4)
        {
            var sb = new StringBuilder();
            int count = 0;

            foreach (char c in input)
            {
                if (c >= 32 && c <= 126)
                {
                    sb.Append(c);
                    count++;
                }
                else
                {
                    sb.Append(count >= minLen ? "\n" : "");
                    count = 0;
                }
            }

            return sb.ToString().Trim();
        }
    }
}
