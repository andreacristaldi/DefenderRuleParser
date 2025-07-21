using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class MacroSourceParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] rawData = reader.ReadBytes(size);
                string decoded = TryDecodeAsciiOrUnicode(rawData);

                decoded = decoded.Trim('\0');
                decoded = decoded.Replace("\r\n", "\n").Replace("\r", "\n");

                var lines = new List<string>(decoded.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries));


                Console.WriteLine($"[MACRO_SOURCE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > Lines: {lines.Count}");

                if (lines.Count > 0)
                {
                    int previewLines = Math.Min(lines.Count, 5);
                    for (int i = 0; i < previewLines; i++)
                        Console.WriteLine($"    → {lines[i]}");

                    if (lines.Count > previewLines)
                        Console.WriteLine("    ...");
                }

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_MACRO_SOURCE",
                        Offset = offset,
                        Pattern = lines,
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] MACRO_SOURCE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string TryDecodeAsciiOrUnicode(byte[] data)
        {
            string ascii = Encoding.ASCII.GetString(data);
            string utf16 = Encoding.Unicode.GetString(data);

            int asciiScore = CountPrintable(ascii);
            int utf16Score = CountPrintable(utf16);

            return (utf16Score > asciiScore) ? utf16 : ascii;
        }

        private int CountPrintable(string str)
        {
            int count = 0;
            foreach (char c in str)
            {
                if (c >= 32 && c <= 126 || c == '\n')
                    count++;
            }
            return count;
        }
    }
}
