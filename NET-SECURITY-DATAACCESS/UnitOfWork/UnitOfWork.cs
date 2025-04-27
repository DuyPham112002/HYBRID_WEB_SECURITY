using NET_SECURITY_DATAACCESS.Entities;
using NET_SECURITY_DATAACCESS.Repository.Sqliescape;
using NET_SECURITY_DATAACCESS.Repository.Sqlilogical;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NET_SECURITY_DATAACCESS.UnitOfWork
{
    public class UnitOfWork : IUnitOfWork   
    {
        private readonly NetsecurityContext _context;

        public ISqliescapeRepository Sqliescape { get; private set; }

        public ISqlilogicalRepository Sqlilogical { get; private set; }

        public UnitOfWork(NetsecurityContext context)
        {
            _context = context;
            Sqliescape = new SqliescapeRepository(context);
            Sqlilogical = new SqlilogicalRepository(context);
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        public void Detach()
        {
            _context.ChangeTracker.Clear();
        }
        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
