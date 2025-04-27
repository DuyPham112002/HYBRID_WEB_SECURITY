using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_MODEL.FileUploadModel
{
    public class FileExtention
    {
        public string Extension { get; set; }
        public List<byte[]> HexSignature { get; set; }
    }
}
