using Google.Protobuf.Collections;
using NET_SECURITY_MODEL.FileUploadModel;

namespace NET_SECURITY_MODEL.GrpcMessageModel
{
    public class RequestModel
    {
        public string Method { get; set; }
        public string Path { get; set; }
        public string Protocol { get; set; }
        public string QueryString { get; set; }
        public string ContentType { get; set; }
        public long? ContentLength { get; set; }
        public string Body { get; set; }
        public bool HasFormContentType { get; set; }
        public MapField<string, string> Headers { get; set; }
        public MapField<string, string> Queries { get; set; }
        public MapField<string, string> Cookies { get; set; }
        public RepeatedField<FileModel> Files { get; set; } = new RepeatedField<FileModel>();
    }
}

