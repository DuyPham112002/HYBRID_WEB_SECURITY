using Google.Protobuf.Collections;
using NET_SECURITY_MODEL.ConfigurationModel;
using NET_SECURITY_MODEL.FileUploadModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAF_SECURITY.FileUploadSecurity
{
    public interface IFileUploadTesting
    {
        Task<FILEInspect> InspectFileExtension(RepeatedField<FileModel> files);
        Task<FILEInspect> InspectFileMalware(RepeatedField<FileModel> files);
    }
}
