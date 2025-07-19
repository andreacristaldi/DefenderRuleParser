using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Models;

namespace DefenderRuleParser2.Parsers
{
    public class SigtreeExtParser : ISignatureParser
    {
        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] data = reader.ReadBytes(size);

                using (var ms = new MemoryStream(data))
                using (var br = new BinaryReader(ms))
                {
                    Console.WriteLine($"[SIGTREE_EXT] Threat ID: {threatId}, Size: {size} bytes");

                    
                    ushort nodeCount = br.ReadUInt16();

                    Console.WriteLine($"  > Node count: {nodeCount}");

                    for (int i = 0; i < nodeCount; i++)
                    {
                        if (br.BaseStream.Position + 6 > br.BaseStream.Length)
                        {
                            Console.WriteLine($"  ⚠ Node #{i} truncated.");
                            break;
                        }

                        ushort nodeType = br.ReadUInt16();
                        ushort nodeSize = br.ReadUInt16();
                        ushort flags = br.ReadUInt16();

                        Console.WriteLine($"    └ Node #{i}: Type={nodeType:X4}, Size={nodeSize}, Flags={flags:X4}");

                        if (br.BaseStream.Position + nodeSize > br.BaseStream.Length)
                        {
                            Console.WriteLine($"    ⛔ Node data exceeds bounds, skipping.");
                            break;
                        }

                        byte[] nodeData = br.ReadBytes(nodeSize);
                        string hex = BitConverter.ToString(nodeData).Replace("-", " ");

                        if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                        {
                            threat.Signatures.Add(new SignatureEntry
                            {
                                Type = "SIGNATURE_TYPE_SIGTREE_EXT",
                                Offset = offset,
                                Pattern = new List<string> { hex },
                                Parsed = false
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SIGTREE_EXT ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
            }
            finally
            {
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }
    }
}
