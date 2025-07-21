using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class PepCodeParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hexLinesForConsole = new List<string>();
            var hexLinesForExport = new List<string>();

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                for (int i = 0; i < buffer.Length; i += 16)
                {
                    string line = $"{(offset + i):X8} ";
                    string clean = "";

                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < buffer.Length)
                        {
                            byte b = buffer[i + j];
                            line += $"{b:X2} ";
                            clean += $"{b:X2} ";
                        }
                        else
                        {
                            line += "   ";
                        }
                    }

                    hexLinesForConsole.Add(line.TrimEnd());
                    hexLinesForExport.Add(clean.TrimEnd());
                }

                Console.WriteLine($"[PEPCODE] Threat ID: {threatId}, Size: {size} bytes");
                Console.WriteLine("  > Hex dump:");
                foreach (var line in hexLinesForConsole)
                    Console.WriteLine("    " + line);

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PEPCODE",
                        Offset = offset,
                        Pattern = hexLinesForExport
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] PEPCODE ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}

