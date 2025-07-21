using DefenderRuleParser2;
using DefenderRuleParser2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DefenderRuleParser2.Parsers
{
    public class RegKeyParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                using (MemoryStream ms = new MemoryStream(buffer))
                using (BinaryReader br = new BinaryReader(ms))
                {
                    ushort unknown = br.ReadUInt16();

                    byte sizeLow = br.ReadByte();
                    byte sizeHigh = br.ReadByte();
                    int regKeySize = sizeLow | (sizeHigh << 8);

                    byte[] keyBytes = br.ReadBytes(size - 4);
                    string regKey = Encoding.UTF8.GetString(keyBytes).Trim('\0');

                    Console.WriteLine($"[REGKEY] Threat ID: {threatId}, Size: {{size}} bytes\");");
                    Console.WriteLine("  > Key:   " + regKey); 

                    if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_REGKEY",
                            Offset = offset,
                            Pattern = new List<string> { regKey },
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] REGKEY ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
