using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class LocalHashParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;
            var hashes = new List<string>();

            try
            {
                byte[] buffer = reader.ReadBytes(size);

                for (int i = 0; i < buffer.Length;)
                {
                    int remaining = buffer.Length - i;

                    // Esempio: blocchi di 20 bytes (es. SHA1) o 16 (MD5)
                    int hashLen = remaining >= 20 ? 20 : remaining;

                    byte[] hash = new byte[hashLen];
                    Array.Copy(buffer, i, hash, 0, hashLen);

                    hashes.Add(BitConverter.ToString(hash).Replace("-", ""));
                    i += hashLen;
                }

                Console.WriteLine($"[LOCALHASH] Threat ID: {threatId}, Hashes: {hashes.Count}");
                Console.WriteLine("  > Hashes:\n" + string.Join(Environment.NewLine, hashes));

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_LOCALHASH",
                        Offset = offset,
                        Pattern = hashes
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] LOCALHASH ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {

                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
