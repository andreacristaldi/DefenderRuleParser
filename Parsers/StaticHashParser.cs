using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class StaticHashParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                string hex = BitConverter.ToString(buffer).Replace("-", "");

                bool isStandardLength = (size == 16 || size == 20 || size == 32);
                bool isEmpty = buffer.Length == 0 || IsAllZeros(buffer);

                Console.WriteLine($"[HASH] Threat ID: {threatId} | Size: {size} bytes | {(isStandardLength ? "Standard" : "Non-standard")}");
                Console.WriteLine($"  > Hex: {hex}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_STATIC",
                        Offset = offset,
                        Pattern = isEmpty ? new List<string>() : new List<string> { hex },
                        Parsed = isStandardLength && !isEmpty
                    });
                }
            }
            
            catch (Exception ex)
            {
                Console.WriteLine($"[!] STATIC ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private bool IsAllZeros(byte[] data)
        {
            foreach (byte b in data)
            {
                if (b != 0) return false;
            }
            return true;
        }
    }
}
