using System;
using System.Collections.Generic;
using System.IO;
using DefenderRuleParser2.Parsers;
using DefenderRuleParser2;
using System.CodeDom.Compiler;

namespace DefenderRuleParser2
{
    public static class SignatureDispatcher
    {
        private static readonly Dictionary<string, ISignatureParser> Parsers = new Dictionary<string, ISignatureParser>
        {

            // Heuristic String-based detection (PE/ELF/MAC/JS/etc.)
            { "SIGNATURE_TYPE_PEHSTR", new HstrParser() },
            { "SIGNATURE_TYPE_PEHSTR_EXT", new HstrParser() },
            { "SIGNATURE_TYPE_PEHSTR_EXT2", new HstrParser() },
            { "SIGNATURE_TYPE_ELFHSTR_EXT", new ElfHstrExtParser() },
            { "SIGNATURE_TYPE_MACHOHSTR_EXT", new MachOHstrExtParser() },
            { "SIGNATURE_TYPE_JAVAHSTR_EXT", new JavaHstrExtParser() },
            { "SIGNATURE_TYPE_DMGHSTR_EXT", new DmgHstrExtParser() },
            { "SIGNATURE_TYPE_ARHSTR_EXT", new ArhstrExtParser() },
            { "SIGNATURE_TYPE_MDBHSTR_EXT", new MdbHstrExtParser() },
            { "SIGNATURE_TYPE_SWFHSTR_EXT", new SwfHstrExtParser() },
            { "SIGNATURE_TYPE_AUTOITHSTR_EXT", new AutoItHstrExtParser() },
            { "SIGNATURE_TYPE_INNOHSTR_EXT", new InnoHstrExtParser() },
            { "SIGNATURE_TYPE_CMDHSTR_EXT", new CmdHstrExtParser() },
            { "SIGNATURE_TYPE_DEXHSTR_EXT", new DexHstrExtParser() },
            { "SIGNATURE_TYPE_MACROHSTR_EXT", new MacroHstrExtParser() },
            { "SIGNATURE_TYPE_POLYVIR32", new Polyvir32Parser() },
            
            // Registry keys
            { "SIGNATURE_TYPE_REGKEY", new RegKeyParser() },

            // File system
            { "SIGNATURE_TYPE_FILEPATH", new FilePathParser() },
            { "SIGNATURE_TYPE_FILENAME", new FilePathParser() },
            { "SIGNATURE_TYPE_FOLDERNAME", new FilePathParser() },
            { "SIGNATURE_TYPE_ASEP_FILEPATH", new AsepFilepathParser() },
            { "SIGNATURE_TYPE_ASEP_FOLDERNAME", new AsepFoldernameParser() },
            
            // Static hashes / fingerprints
            { "SIGNATURE_TYPE_STATIC", new StaticHashParser() },
            { "SIGNATURE_TYPE_LOCALHASH", new LocalHashParser() },
            { "SIGNATURE_TYPE_PESTATIC", new PestaticParser() },
            { "SIGNATURE_TYPE_PESTATICEX", new PestaticExParser() },
            { "SIGNATURE_TYPE_KVIR32", new Kvir32Parser() },
            { "SIGNATURE_TYPE_KCRCE", new KcrceParser() },
            { "SIGNATURE_TYPE_KCRCEX", new KcrcExParser() },
            { "SIGNATURE_TYPE_KPATEX", new KpatExParser() },
            { "SIGNATURE_TYPE_KPAT", new KpatParser() },
            { "SIGNATURE_TYPE_CKSIMPLEREC", new CkSimpleRecParser() },
            { "SIGNATURE_TYPE_CKOLDREC", new CkOldRecParser() },
            { "SIGNATURE_TYPE_FRIENDLYFILE_SHA256", new FriendlyFileSha256Parser() },
            { "SIGNATURE_TYPE_BOOT", new BootParser() },
            { "SIGNATURE_TYPE_PEBMPAT", new PebmpatParser() },

            // Heuristics via pattern match or scripting
            { "SIGNATURE_TYPE_PATTMATCH", new PattmatchParser() },
            { "SIGNATURE_TYPE_PATTMATCH_V2", new PattmatchParser() },

            // Scripting patterns (e.g., VBScript, JS, AutoIt)
            { "SIGNATURE_TYPE_MACRO_PCODE", new MacroPcodeParser() },
            { "SIGNATURE_TYPE_MACRO_PCODE64", new MacroPcode64Parser() },
            { "SIGNATURE_TYPE_MACRO_SOURCE", new MacroSourceParser() },
            { "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE", new TargetScriptPcodeParser() },
            { "SIGNATURE_TYPE_UFSP_DISABLE", new UfspDisableParser() },

            // Lua embedded
            { "SIGNATURE_TYPE_LUASTANDALONE", new LuaParser() },

            // Signature trees (relationships, dependencies)
            { "SIGNATURE_TYPE_SIGTREE", new SigtreeParser() },
            { "SIGNATURE_TYPE_SIGTREE_EXT", new SigtreeExtParser() },
            { "SIGNATURE_TYPE_SIGTREE_BM", new SigtreeBmParser() },
            { "SIGNATURE_TYPE_BM_INFO", new BmInfoParser() },

            // Platform / version / behavior switches
            { "SIGNATURE_TYPE_THREAD_X86", new ThreadX86Parser() },
            { "SIGNATURE_TYPE_VERSIONCHECK", new VersionCheckParser() },
            { "SIGNATURE_TYPE_DEFAULTS", new DefaultsParser() },
            
            // Identifier match / naming
            { "SIGNATURE_TYPE_NID", new NidParser() },
            { "SIGNATURE_TYPE_SNID", new SnidParser() },

            // NScript-specific variants
            { "SIGNATURE_TYPE_NSCRIPT_NORMAL", new NscriptNormalParser() },
            { "SIGNATURE_TYPE_NSCRIPT_CURE", new NscriptCureParser() },
            { "SIGNATURE_TYPE_NSCRIPT_SP", new NscriptSpParser() },
            { "SIGNATURE_TYPE_NSCRIPT_BRUTE", new NscriptBruteParser() },

            // Execution structures
            { "SIGNATURE_TYPE_PEPCODE", new PepCodeParser() },
            { "SIGNATURE_TYPE_IL_PATTERN", new IlPatternParser() },

            // Aggregated detections
            { "SIGNATURE_TYPE_AAGGREGATOR", new AaggregatorParser() },
            { "SIGNATURE_TYPE_AAGGREGATOREX", new AaggregatorExParser() },

            // File operation / analysis
            { "SIGNATURE_TYPE_FOPEX", new FopexParser() },
            { "SIGNATURE_TYPE_FOP", new FopParser() },

            // App reputation / telemetry
            { "SIGNATURE_TYPE_PUA_APPMAP", new PuaAppMapParser() },
            { "SIGNATURE_TYPE_NDAT", new NdatParser() },



        };

        public static void Dispatch(string sigType, BinaryReader reader, int size, uint threatId)
        {
            long offset = reader.BaseStream.Position;

            ISignatureParser parser;
            if (Parsers.TryGetValue(sigType, out parser))
            {
                parser.Parse(reader, size, threatId);
            }
            else
            {
                Console.WriteLine("[!] No parser implemented for signature type: " + sigType);
                reader.BaseStream.Seek(size, SeekOrigin.Current); // Skip unknown signature block
            }

            if (ThreatDatabase.TryGetThreat(threatId, out var threat))
            {
                if (!threat.SignatureStats.ContainsKey(sigType))
                    threat.SignatureStats[sigType] = 0;

                threat.SignatureStats[sigType]++;

                threat.Signatures.Add(new SignatureEntry
                {
                    Type = sigType,
                    Offset = offset
                    // Pattern 
                });
            }



        }
    }
}
