using Google.Protobuf.Collections;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RequestCultureMiddleware.Model
{
    public class RequestMessage
    {
        public string Method { get; set; }
        public string Path { get; set; }
        public string Protocol { get; set; }
        public string QueryString { get; set; }
        public string ContentType { get; set; }
        public long? ContentLength { get; set; }
        public bool HasFormContentType { get; set; }
        public string? Body { get; set; }
        public Dictionary<string, string> Queries { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public Dictionary<string, string> Cookies { get; set; }
        public RepeatedField<FileRequest> Files { get; set; } = new RepeatedField<FileRequest>();
    }
}
