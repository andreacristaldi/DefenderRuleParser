using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class VersionCheckParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(buffer).Replace("-", " ");

                Console.WriteLine($"[VERSIONCHECK] Threat ID: {threatId}, Size: {size} bytes");
                //Console.WriteLine($"  > Hex Dump (truncated): {hexDump.Substring(0, Math.Min(100, hexDump.Length))}...");
                Console.WriteLine($"  > Hex Dump: {hexDump}");


                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_VERSIONCHECK",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] VERSIONCHECK ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
