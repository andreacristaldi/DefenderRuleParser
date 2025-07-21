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

                // Formattazione dump con indirizzi per console
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

                // Esportazione raw (senza indirizzi) per HTML/JSON/YARA
                var hexLines = new List<string>();
                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string hexLine = "";
                    for (int j = 0; j < 16 && i + j < buffer.Length; j++)
                        hexLine += $"{buffer[i + j]:X2} ";
                    hexLines.Add(hexLine.TrimEnd());
                }

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_NID",
                        Offset = offset,
                        Pattern = hexLines,
                        Parsed = false
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] NID ❌ Error parsing at 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
