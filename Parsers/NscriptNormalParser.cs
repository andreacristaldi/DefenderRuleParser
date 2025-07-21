using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NscriptNormalParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                string hex = BitConverter.ToString(data).Replace("-", " ");
                string ascii = ExtractAscii(data);

                Console.WriteLine($"[NSCRIPT_NORMAL] Threat ID: {threatId}, Size: {size} bytes");
                //Console.WriteLine($"  > ASCII Preview: {Truncate(ascii, 80)}");
                Console.WriteLine($"  > ASCII: {ascii}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NSCRIPT_NORMAL",
                        Offset = offset,
                        Pattern = new List<string> { hex },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NSCRIPT_NORMAL ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
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

        private string ExtractAscii(byte[] data)
        {
            var sb = new System.Text.StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }
            return sb.ToString();
        }
    }
}
