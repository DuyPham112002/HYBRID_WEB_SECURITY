using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.FileUploadModel
{
    public class FileModel
    {
        public long Length { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public byte[] FileContent { get; set; }
        public string FileName { get; set; }
    }
}
