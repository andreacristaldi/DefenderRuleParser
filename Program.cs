// Cybersec4.com DefenderRules
// Author: Andrea Cristaldi 2025 - https://github.com/andreacristaldi

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace DefenderRuleParser2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Cybersec4.com - Defender Rule Parser");

            if (args.Length < 1)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  DefenderRuleParser <fileOrFolder> [--recursive] [--skip-existing]");
                return;
            }

            string inputPath = args[0];
            bool recursive = args.Contains("--recursive", StringComparer.OrdinalIgnoreCase);
            bool skipExisting = args.Contains("--skip-existing", StringComparer.OrdinalIgnoreCase);

            Console.WriteLine("[+] Loading threat dictionary from 'defender.csv'...");
            string filePath = "defender.csv";
            if (!File.Exists(filePath))
            {
                Console.WriteLine("Threat dictionary not found. Attempting to retrieve using PowerShell...");

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo()
                    {
                        FileName = "powershell.exe",
                        Arguments = "Get-MpThreatCatalog | Export-Csv -Path ./defender.csv -NoTypeInformation",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (Process process = new Process())
                    {
                        process.StartInfo = psi;
                        process.Start();

                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();

                        process.WaitForExit();

                        if (process.ExitCode != 0 || !File.Exists(filePath))
                        {
                            Console.WriteLine("PowerShell execution failed or defender.csv not created.\n" + error);
                            Console.WriteLine("Ensure PowerShell is available, Windows Defender is installed, and you have sufficient permissions.");
                            return;
                        }

                        Console.WriteLine("Threat catalog successfully retrieved.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error executing PowerShell: " + ex.Message);
                    Console.WriteLine("Make sure PowerShell is installed and accessible, and that script execution is not restricted.");
                    return;
                }
            }




            ThreatDatabase.Load(filePath);

            List<string> binFiles = new List<string>();

            if (File.Exists(inputPath) && inputPath.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
            {
                binFiles.Add(inputPath);
            }
            else if (Directory.Exists(inputPath))
            {
                SearchOption searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                var allBins = Directory.GetFiles(inputPath, "*.bin", searchOption);

                foreach (var bin in allBins)
                {
                    string jsonPath = Path.ChangeExtension(bin, ".json");

                    if (skipExisting && File.Exists(jsonPath))
                    {
                        Console.WriteLine($"[>] Skipping {Path.GetFileName(bin)} (JSON already exists)");
                        continue;
                    }

                    binFiles.Add(bin);
                }
            }
            else
            {
                Console.WriteLine("[!] Invalid file or folder path.");
                return;
            }

            foreach (string binPath in binFiles)
            {
                Console.WriteLine($"\n[+] Processing: {binPath}");

                try
                {
                    using (FileStream fs = new FileStream(binPath, FileMode.Open, FileAccess.Read))
                    using (BinaryReader reader = new BinaryReader(fs))
                    {
                        SignatureReader.ExtractSignatures(reader, binPath);
                    }

                    string outputJson = Path.Combine(
                        Path.GetDirectoryName(binPath),
                        Path.GetFileNameWithoutExtension(binPath) + ".json"
                    );

                    Exporter.SaveAllThreats(Path.GetDirectoryName(outputJson), Path.GetFileNameWithoutExtension(outputJson));
                    Console.WriteLine($"[✓] Exported: {outputJson}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Failed to process {binPath}: {ex.Message}");
                }
            }

            Console.WriteLine("\n[✓] Parsing completed. Press any key to exit.");
            Console.ReadKey();
        }
    }
}
