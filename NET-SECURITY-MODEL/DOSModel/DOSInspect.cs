using NET_SECURITY_MODEL.SQLIModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.DOSModel
{
    public class DOSInspect
    {
        public bool IsDrop { get; set; }
        public int Status { get; set; }
        public string? Message { get; set; }

        public static DOSInspect Response(bool drop, int status, string message = null)
        {
            return new DOSInspect { IsDrop = drop, Status = status, Message = message };
        }
    }
}
