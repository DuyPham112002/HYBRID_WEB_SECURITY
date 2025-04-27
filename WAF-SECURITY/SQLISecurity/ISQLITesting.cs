using Microsoft.AspNetCore.Http;
using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.SQLIModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAF_SECURITY.SQLISecurity
{
    public interface ISQLITesting
    {
        Task<SQLIInspect> IsEscapeSQLI(RequestModel request);
        Task<SQLIInspect> IsLogicalOperateSQLI(RequestModel request);
        Task<SQLIInspect> IsDefaultPatternSBSQLI(RequestModel request);
        Task<SQLIInspect> IsRExpressionSBSQLI(RequestModel request);
        Task<SQLIInspect> IsCRSRuleSBSQLI(RequestModel request);
        Task<SQLIInspect> IsCTRuleSBSQLI(RequestModel request);
    }
}
