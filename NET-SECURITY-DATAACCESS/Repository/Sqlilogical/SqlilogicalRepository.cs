using Microsoft.EntityFrameworkCore;
using NET_SECURITY_DATAACCESS.Entities;
using NET_SECURITY_DATAACCESS.Repository.Base;
using NET_SECURITY_DATAACCESS.Repository.Sqliescape;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.Repository.Sqlilogical
{
    public class SqlilogicalRepository : Repository<Entities.Sqlilogical>, ISqlilogicalRepository
    {
        private readonly NetsecurityContext _context;
        public SqlilogicalRepository(NetsecurityContext context) : base(context)
        {
            _context = context;
        }
        public void Update(Entities.Sqlilogical sqlilogical)
        {
            _context.Sqlilogicals.Update(sqlilogical);
        }
    }
}
