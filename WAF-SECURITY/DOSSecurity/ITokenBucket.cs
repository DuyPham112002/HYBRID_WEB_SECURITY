using NET_SECURITY_MODEL.DOSModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAF_SECURITY.DOSSecurity
{
    public interface ITokenBucket
    {
        DOSInspect UseToken();
    }
}
