using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.XSSModel
{
    public class XSSRuleModel
    {
        public int Id { get; set; }
        public string Pattern { get; set; }
        public string Ignore { get; set; }
        public string Message { get; set; }
        public string Target { get; set; }
        public string[]? Targets { get; set; }
        public string Type { get; set; }
        public string Transformation { get; set; }
        public string[]? Transformations { get; set; }
    }
}
