using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DefenderRuleParser2
{
    public interface ISignatureParser
    {
        void Parse(BinaryReader reader, int size, uint threatId);
    }
}
