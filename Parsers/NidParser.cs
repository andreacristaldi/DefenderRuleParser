using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class NidParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var dump = new List<string>();

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string line = $"{(offset + i):X8} ";
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < buffer.Length)
                            line += $"{buffer[i + j]:X2} ";
                        else
                            line += "   ";
                    }
                    dump.Add(line.TrimEnd());
                }

                Console.WriteLine($"[NID] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Dump:\n" + string.Join(Environment.NewLine, dump));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NID",
                        Offset = offset,
                        Pattern = dump
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NID parsing error at 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
