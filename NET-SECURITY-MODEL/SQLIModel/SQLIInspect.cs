using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.SQLIModel
{
    public class SQLIInspect
    {
        public bool IsViolated { get; set; }
        public int Status { get; set; }
        public string? Message { get; set; }

        public static SQLIInspect Response(bool isViolated, int status, string message = null)
        {
            return new SQLIInspect { IsViolated = isViolated, Status = status,Message = message };
        }
    }
}
