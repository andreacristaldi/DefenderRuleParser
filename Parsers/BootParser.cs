using System;
using System.IO;
using System.Collections.Generic;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class BootParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(data).Replace("-", " ");

                Console.WriteLine($"[BOOT] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex: " + hexDump);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_BOOT",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false
                    });
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine($"[BOOT] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private string Truncate(string input, int maxLength)
        {
            return string.IsNullOrEmpty(input) || input.Length <= maxLength
                ? input
                : input.Substring(0, maxLength) + "...";
        }
    }
}
