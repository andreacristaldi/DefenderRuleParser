using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class PestaticParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hexLinesConsole = new List<string>();
            var hexLinesExport = new List<string>();

            try
            {
                byte[] data = reader.ReadBytes(size);

                for (int i = 0; i < data.Length; i += 16)
                {
                    string consoleLine = $"{(offset + i):X8} ";
                    string exportLine = "";

                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < data.Length)
                        {
                            byte b = data[i + j];
                            consoleLine += $"{b:X2} ";
                            exportLine += $"{b:X2} ";
                        }
                        else
                        {
                            consoleLine += "   ";
                        }
                    }

                    hexLinesConsole.Add(consoleLine.TrimEnd());
                    hexLinesExport.Add(exportLine.TrimEnd());
                }

                Console.WriteLine($"[PESTATIC] Threat ID: {threatId}, Dumped {size} bytes");
                Console.WriteLine("  > Hex:\n" + string.Join(Environment.NewLine, hexLinesConsole));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_PESTATIC",
                        Offset = offset,
                        Pattern = hexLinesExport
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] PESTATIC ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
