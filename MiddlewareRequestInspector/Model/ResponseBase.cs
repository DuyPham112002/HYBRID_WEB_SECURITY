using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RequestCultureMiddleware.Model
{
    public class ResponseBase
    {
        public bool IsSecurity { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; }
    }
}
