using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.ConfigurationModel
{
    public class AppConfiguration
    {
        public RateLimit RateLimit { get; set; }
        public InspectFile InspectFile { get; set; }
        public VerifyType VerifyType { get; set; }
    }
    public class InspectFile
    {
        public bool Enabled { get; set; }
    }
    public class VerifyType
    {
        public List<string> FileExtensionsToScan { get; set; }
        public List<string> FileExtensionsNormal { get; set; }
    }
    public class RateLimit
    {
        public bool Enabled { get; set; }
    }
}
