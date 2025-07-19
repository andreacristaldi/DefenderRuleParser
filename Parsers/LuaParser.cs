using DefenderRuleParser2;
using DefenderRuleParser2.Models;
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace DefenderRuleParser2.Parsers
{
    public class LuaParser : ISignatureParser
    {
        private static readonly byte[] LuaHeader = new byte[] { 0x1B, 0x4C, 0x75, 0x61 }; // \x1bLua

        public void Parse(BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            try
            {
                byte[] buffer = reader.ReadBytes(size);
                int headerIndex = FindLuaHeader(buffer);

                if (headerIndex == -1)
                {
                    Console.WriteLine($"[LUA] Threat ID: {threatId} | Lua header not found.");
                    return;
                }

                byte[] luaCode = new byte[buffer.Length - headerIndex];
                Array.Copy(buffer, headerIndex, luaCode, 0, luaCode.Length);

                string luaPath = $"lua_script_{threatId}.lua";
                File.WriteAllBytes(luaPath, luaCode);

                Console.WriteLine($"[LUA] Threat ID: {threatId} | Extracted Lua script to: {luaPath}");

                if (ThreatDatabase.TryGetThreat(threatId, out var threat))
                {
                    threat.Signatures.Add(new SignatureEntry
                    {
                        Type = "SIGNATURE_TYPE_LUASTANDALONE",
                        Offset = offset,
                        Pattern = new List<string> { $"Extracted: {luaPath}" },
                        Parsed = true
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LUA] ❌ Error parsing at offset 0x{offset:X}: {ex.Message}");
                reader.BaseStream.Seek(offset + size, SeekOrigin.Begin);
            }
        }

        private int FindLuaHeader(byte[] data)
        {
            for (int i = 0; i <= data.Length - LuaHeader.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < LuaHeader.Length; j++)
                {
                    if (data[i + j] != LuaHeader[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }
    }
}
