using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class UfspDisableParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] raw = reader.ReadBytes(size);
                string hexPattern = BitConverter.ToString(raw).Replace("-", " ");

                Console.WriteLine($"[UFSP_DISABLE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex:   " + hexPattern);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_UFSP_DISABLE",
                        Offset = offset,
                        Pattern = new List<string> { hexPattern },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] UFSP_DISABLE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

