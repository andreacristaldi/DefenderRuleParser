using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class TargetScriptPcodeParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] pcodeBytes = reader.ReadBytes(size);
                string hexPattern = BitConverter.ToString(pcodeBytes).Replace("-", " ");

                Console.WriteLine($"[PCODE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex:   " + hexPattern);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE",
                        Offset = offset,
                        Pattern = new List<string> { hexPattern },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PCODE] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

