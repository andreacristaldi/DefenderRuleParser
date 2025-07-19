using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace DefenderRuleParser2
{
    public static class SignatureReader
    {
        public static void ExtractSignatures(BinaryReader reader, string filePath)
        {
            long fileLength = reader.BaseStream.Length;
            uint currentThreatId = 0;

            while (reader.BaseStream.Position < fileLength)
            {
                long position = reader.BaseStream.Position;

                try
                {
                    byte typeByte = reader.ReadByte();
                    string sigType = SignatureTypeMapper.GetSignatureType(typeByte);

                    byte sizeLow = reader.ReadByte();
                    ushort sizeHigh = reader.ReadUInt16();
                    int size = sizeLow | (sizeHigh << 8);
                    long endPosition = reader.BaseStream.Position + size;

                    Console.WriteLine($"[>] Found signature: {sigType} @0x{position:X}");

                    if (sigType == "SIGNATURE_TYPE_THREAT_BEGIN")
                    {
                        currentThreatId = reader.ReadUInt32();

                        Threat threat = ThreatDatabase.CreateOrUpdateThreat(currentThreatId, position);
                        Console.WriteLine($"[+] Threat Begin: ID={currentThreatId} Name='{threat.ThreatName}'");
                    }
                    else if (sigType == "SIGNATURE_TYPE_THREAT_END")
                    {
                        byte[] threatIdBytes = reader.ReadBytes(4);
                        uint endThreatId = BitConverter.ToUInt32(threatIdBytes, 0);

                        if (ThreatDatabase.TryUpdateThreatEnd(endThreatId, endPosition))
                        {
                            Console.WriteLine($"[✓] Threat End: ID={endThreatId} @0x{endPosition:X}");
                        }
                    }
                    else if (sigType != "SIGNATURE_TYPE_UNKNOWN")
                    {
                        SignatureDispatcher.Dispatch(sigType, reader, size, currentThreatId);
                    }

                    reader.BaseStream.Position = endPosition;
                }
                catch (EndOfStreamException)
                {
                    Console.WriteLine("[!] Reached unexpected end of stream.");
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Exception at 0x{position:X}: {ex.Message}");
                    break;
                }
            }
        }
    }
}
