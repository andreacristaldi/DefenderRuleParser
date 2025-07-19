using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class AsepFilepathParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                using (var ms = new MemoryStream(buffer))
                using (var br = new BinaryReader(ms))
                {
                    uint header = br.ReadUInt32();         // Ignored for now
                    ushort pathLength = br.ReadUInt16();   // Path length

                    if (pathLength > 0 && pathLength <= ms.Length - ms.Position)
                    {
                        byte[] pathBytes = br.ReadBytes(pathLength);
                        string path = Encoding.UTF8.GetString(pathBytes).Trim('\0');

                        Console.WriteLine($"[ASEP_FILEPATH] Threat ID: {threatId}");
                        Console.WriteLine($"  > Path: {path}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_ASEP_FILEPATH",
                                Offset = offset,
                                Pattern = new List<string> { path },
                                Parsed = true
                            });
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[ASEP_FILEPATH] ⚠ Invalid path length {pathLength} at Threat {threatId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ASEP_FILEPATH ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
