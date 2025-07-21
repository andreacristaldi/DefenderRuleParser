using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class ThreadX86Parser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hexDump = new List<string>();

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
                    hexDump.Add(line.TrimEnd());
                }

                Console.WriteLine($"[THREAD_X86] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex Dump:\n" + string.Join(Environment.NewLine, hexDump));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_THREAD_X86",
                        Offset = offset,
                        Pattern = hexDump,
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] THREAD_X86 ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

