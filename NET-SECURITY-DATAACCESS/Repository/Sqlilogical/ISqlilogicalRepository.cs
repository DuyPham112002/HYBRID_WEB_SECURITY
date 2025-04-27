using NET_SECURITY_DATAACCESS.Repository.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.Repository.Sqlilogical
{
    public interface ISqlilogicalRepository : IRepository<Entities.Sqlilogical>
    {
        void Update(Entities.Sqlilogical sqlilogical);
    }
}
