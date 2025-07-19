using System;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MacroSourceParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long baseOffset = reader.BaseStream.Position;

            try
            {
                byte[] rawData = reader.ReadBytes(size);
                string sourceText = TryDecodeAsciiOrUnicode(rawData);

                Console.WriteLine($"[MACRO_SOURCE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Text: {sourceText}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_MACRO_SOURCE",
                        Offset = baseOffset,
                        Pattern = new System.Collections.Generic.List<string> { sourceText },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACRO_SOURCE ❌ Error parsing at offset 0x{baseOffset:X}: {ex.Message}");
                reader.BaseStream.Seek(baseOffset + size, SeekOrigin.Begin);
            }
        }

        private string TryDecodeAsciiOrUnicode(byte[] data)
        {
            // Prova UTF-8 prima, poi UTF-16
            string ascii = Encoding.ASCII.GetString(data);
            string utf16 = Encoding.Unicode.GetString(data);

            // Heuristic: pick the one with more printable characters
            int asciiScore = CountPrintable(ascii);
            int utf16Score = CountPrintable(utf16);

            return (utf16Score > asciiScore) ? utf16 : ascii;
        }

        private int CountPrintable(string str)
        {
            int count = 0;
            foreach (char c in str)
            {
                if (c >= 32 && c <= 126)
                    count++;
            }
            return count;
        }
    }
}
