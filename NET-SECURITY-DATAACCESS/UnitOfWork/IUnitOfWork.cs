using NET_SECURITY_DATAACCESS.Repository.Sqliescape;
using NET_SECURITY_DATAACCESS.Repository.Sqlilogical;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.UnitOfWork
{
    public interface IUnitOfWork
    {
        ISqliescapeRepository Sqliescape { get; }
        ISqlilogicalRepository Sqlilogical { get; }

        Task SaveAsync();
    }
}
