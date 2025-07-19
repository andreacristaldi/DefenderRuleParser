using System.Text;
using System;

public static class HexDumper
{
    public static void Print(string title, byte[] data, long offset)
    {
        Console.WriteLine();
        Console.WriteLine($"{title}");
        for (int i = 0; i < data.Length; i += 16)
        {
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();

            for (int j = 0; j < 16; j++)
            {
                if (i + j < data.Length)
                {
                    byte b = data[i + j];
                    hex.AppendFormat("{0:X2} ", b);
                    ascii.Append((b >= 32 && b <= 126) ? (char)b : '.');
                }
                else
                {
                    hex.Append("   ");
                    ascii.Append(" ");
                }
            }

            Console.WriteLine($"{offset + i:X8} {hex} {ascii}");
        }
    }
}
