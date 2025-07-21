using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NscriptCureParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                string asciiPreview = Encoding.ASCII.GetString(buffer);
                string extractedText = ExtractAsciiStrings(asciiPreview, 4);

                // Console dump con offset
                var hexDump = new List<string>();
                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string line = $"{(offset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < buffer.Length)
                            line += $"{buffer[i + j]:X2} ";
                        else
                            line += "   ";
                    }
                    hexDump.Add(line.TrimEnd());
                }

                Console.WriteLine($"[NSCRIPT_CURE] Threat ID: {threatId}, Size: {size} bytes");
                if (!string.IsNullOrWhiteSpace(extractedText))
                    Console.WriteLine("  > Embedded text: " + extractedText);
                Console.WriteLine("  > Hex:\n" + string.Join(Environment.NewLine, hexDump));

                // Clean hex dump for export (no offsets)
                var hexExport = new List<string>();
                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string line = "";
                    for (int j = 0; j < 16 && i + j < buffer.Length; j++)
                        line += $"{buffer[i + j]:X2} ";
                    hexExport.Add(line.TrimEnd());
                }

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    var pattern = new List<string>();
                    if (!string.IsNullOrWhiteSpace(extractedText))
                        pattern.Add(extractedText);
                    pattern.AddRange(hexExport);

                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NSCRIPT_CURE",
                        Offset = offset,
                        Pattern = pattern,
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NSCRIPT_CURE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string ExtractAsciiStrings(string input, int minLen)
        {
            var output = new StringBuilder();
            var buffer = new StringBuilder();

            foreach (char c in input)
            {
                if (c >= 32 && c <= 126)
                {
                    buffer.Append(c);
                }
                else
                {
                    if (buffer.Length >= minLen)
                    {
                        output.AppendLine(buffer.ToString());
                    }
                    buffer.Clear();
                }
            }

            if (buffer.Length >= minLen)
            {
                output.AppendLine(buffer.ToString());
            }

            return output.ToString().Trim();
        }
    }
}
