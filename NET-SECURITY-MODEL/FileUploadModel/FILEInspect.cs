using NET_SECURITY_MODEL.SQLIModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.FileUploadModel
{
    public class FILEInspect
    {
        public bool IsClean { get; set; }
        public int Status { get; set; }
        public string? Message { get; set; }

        public static FILEInspect Response(bool isClean, int status, string message = null)
        {
            return new FILEInspect { IsClean = isClean, Status = status, Message = message };
        }
    }
}
