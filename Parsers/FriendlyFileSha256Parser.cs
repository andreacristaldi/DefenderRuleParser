using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class FriendlyFileSha256Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] hashBytes = reader.ReadBytes(size);
                string hash = BitConverter.ToString(hashBytes).Replace("-", "");

                Console.WriteLine($"[FRIENDLYFILE_SHA256] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine($"  > SHA256: {hash}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_FRIENDLYFILE_SHA256",
                        Offset = offset,
                        Pattern = new List<string> { hash },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] FRIENDLYFILE_SHA256 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin); // Safe skip
            }
        }
    }
}
