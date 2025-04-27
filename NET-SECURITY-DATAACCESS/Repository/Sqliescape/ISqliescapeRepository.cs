using NET_SECURITY_DATAACCESS.Repository.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.Repository.Sqliescape
{
    public interface ISqliescapeRepository : IRepository<Entities.Sqliescape>
    {
        void Update(Entities.Sqliescape sqliecape);
    }
}
