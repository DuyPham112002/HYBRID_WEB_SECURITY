using NET_SECURITY_MODEL.SQLIModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.XSSModel
{
    public class XSSInspect
    {
        public bool IsViolated { get; set; }
        public int Status { get; set; }
        public string? Message { get; set; }

        public static XSSInspect Response(bool isViolated, int status, string message = null)
        {
            return new XSSInspect { IsViolated = isViolated, Status = status, Message = message };
        }
    }
}
