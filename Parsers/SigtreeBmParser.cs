using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class SigtreeBmParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                string hexDump = BitConverter.ToString(data).Replace("-", " ");

                Console.WriteLine($"[SIGTREE_BM] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex:   " + hexDump);
                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_SIGTREE_BM",
                        Offset = offset,
                        Pattern = new List<string> { hexDump },
                        Parsed = false 
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SIGTREE_BM ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
