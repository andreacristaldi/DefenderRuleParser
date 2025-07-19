using DefenderRuleParser2;
using DefenderRuleParser2.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DefenderRuleParser2.Parsers
{
    public class FilePathParser : ISignatureParser
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
                    ushort unknown = br.ReadUInt16(); // Ignored

                    byte[] pathBytes = br.ReadBytes(size - 2);
                    string filePath = Encoding.UTF8.GetString(pathBytes).Trim('\0');

                    Console.WriteLine($"[FILE] Threat ID: {threatId}, Size: {size} bytes");
                    Console.WriteLine($"  > Path: {filePath}");

                    if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                    {
                        threat.Signatures.Add(new SignatureEntry
                        {
                            Type = "SIGNATURE_TYPE_FILEPATH",
                            Offset = offset,
                            Pattern = new List<string> { filePath },
                            Parsed = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] FILEPATH ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin); // riposizionamento fallback
            }
        }
    }
}
