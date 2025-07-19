using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DefenderRuleParser2.Models
{
    public class SignatureEntry
    {
        public string Type { get; set; }
        public long Offset { get; set; }
        public string Pattern { get; set; }
    }
}
