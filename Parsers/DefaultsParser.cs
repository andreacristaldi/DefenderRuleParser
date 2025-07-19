using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class DefaultsParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] raw = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(raw).Replace("-", " ");
                string ascii = Encoding.UTF8.GetString(raw).Trim('\0');

                Console.WriteLine($"[DEFAULTS] Threat ID: {threatId}, Size: {size} bytes");
                //Console.WriteLine($"  > ASCII: {Truncate(ascii, 80)}");
                Console.WriteLine($"  > ASCII: {ascii}");
                //Console.WriteLine($"  > HEX:   {Truncate(hexDump, 80)}");
                Console.WriteLine($"  > HEX:   {hexDump}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_DEFAULTS",
                        Offset = offset,
                        Pattern = new List<string> { ascii, hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] DEFAULTS ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string Truncate(string input, int max)
        {
            if (string.IsNullOrEmpty(input)) return input;
            return input.Length > max ? input.Substring(0, max) + "..." : input;
        }
    }
}
