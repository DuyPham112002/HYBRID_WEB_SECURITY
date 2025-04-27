using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.XSSModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAF_SECURITY.XSSSecurity
{
    public interface IXSSTesting
    {
        Task<XSSInspect> IsDefaultPatternSBSXSS(RequestModel request);
        Task<XSSInspect> IsCRSRuleSBSXSS(RequestModel request);
    }
}
