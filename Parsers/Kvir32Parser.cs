using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class Kvir32Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);
                List<string> entries = new List<string>();
                int ptr = 0;

                while (ptr + 16 <= data.Length)
                {
                    byte[] part1 = new byte[4];
                    byte[] part2 = new byte[4];
                    byte[] part3 = new byte[4];

                    Array.Copy(data, ptr, part1, 0, 4);
                    Array.Copy(data, ptr + 4, part2, 0, 4);
                    Array.Copy(data, ptr + 8, part3, 0, 4);

                    string id = $"{BitConverter.ToString(part1)} {BitConverter.ToString(part2)} {BitConverter.ToString(part3)}".Replace("-", "");

                    entries.Add(id);
                    ptr += 16;
                }

                Console.WriteLine($"[KVIR32] Threat ID: {threatId}, Entries: {entries.Count}");
                Console.WriteLine("  > Entries:\n" + string.Join(Environment.NewLine, entries));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_KVIR32",
                        Offset = offset,
                        Pattern = entries
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] KVIR32 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
