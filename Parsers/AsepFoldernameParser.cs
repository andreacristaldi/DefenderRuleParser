using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DefenderRuleParser2;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class AsepFoldernameParser : ISignatureParser
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
                    uint header = br.ReadUInt32();         // Ignored
                    ushort folderLength = br.ReadUInt16();

                    if (folderLength > 0 && folderLength <= ms.Length - ms.Position)
                    {
                        byte[] folderBytes = br.ReadBytes(folderLength);
                        string folder = Encoding.UTF8.GetString(folderBytes).Trim('\0');

                        Console.WriteLine($"[ASEP_FOLDERNAME] Threat ID: {threatId}");
                        Console.WriteLine($"  > Folder: {folder}");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_ASEP_FOLDERNAME",
                                Offset = offset,
                                Pattern = new List<string> { folder },
                                Parsed = true
                            });
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[ASEP_FOLDERNAME] ⚠ Invalid folder length {folderLength} at Threat {threatId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ASEP_FOLDERNAME ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
