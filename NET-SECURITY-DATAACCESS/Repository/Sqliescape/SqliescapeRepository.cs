using NET_SECURITY_DATAACCESS.Entities;
using NET_SECURITY_DATAACCESS.Repository.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.Repository.Sqliescape
{
    public class SqliescapeRepository : Repository<Entities.Sqliescape>, ISqliescapeRepository
    {
        private readonly NetsecurityContext _context;
        public SqliescapeRepository(NetsecurityContext context) : base(context) 
        {
            _context = context;
        }

        public void Update(Entities.Sqliescape sqliescape)
        {
            _context.Sqliescapes.Update(sqliescape);
        }
    }
}
