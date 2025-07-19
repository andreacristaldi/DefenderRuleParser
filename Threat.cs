using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DefenderRuleParser2
{
    public class Threat
    {
        public string ThreatName { get; set; }
        public long BeginPosition { get; set; }
        public long EndPosition { get; set; }

        public Dictionary<string, long> SignatureStats { get; set; } = new Dictionary<string, long>();
        public List<SignatureEntry> Signatures { get; set; } = new List<SignatureEntry>();
    }


    public class SignatureEntry
    {
        public string Type { get; set; }
        public long Offset { get; set; }
        public List<string> Pattern { get; set; } = new List<string>();
        public bool? Parsed { get; set; }
    }
}
