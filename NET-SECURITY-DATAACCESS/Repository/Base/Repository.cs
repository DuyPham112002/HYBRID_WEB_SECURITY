using Microsoft.EntityFrameworkCore;
using NET_SECURITY_DATAACCESS.Entities;
using System.Linq.Expressions;

namespace NET_SECURITY_DATAACCESS.Repository.Base
{
	public class Repository<T> : IRepository<T> where T : class
	{
		private readonly NetsecurityContext _db;
		internal DbSet<T> dbSet;

		public Repository(NetsecurityContext db)
		{
			_db = db;
			this.dbSet = _db.Set<T>();
		}

		public async Task AddAsync(T entity)
		{
			await dbSet.AddAsync(entity);
		}

		public async Task<T> GetAsync(string id)
		{
			return await dbSet.FindAsync(id);
		}



		public async Task<List<T>> GetAllAsync(Expression<Func<T, bool>> filter = null, Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null, string includeProperties = null)
		{
			IQueryable<T> query = dbSet;

			if (filter != null)
			{
				query = query.Where(filter);
			}

			if (includeProperties != null)
			{
				foreach (var includeProp in
					includeProperties.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
				{
					query = query.Include(includeProp);
				}
			}

			if (orderBy != null)
			{
				return (await orderBy(query).ToListAsync());
			}
			return (await query.ToListAsync());
		}

		public async Task<T> GetFirstOrDefaultAsync(Expression<Func<T, bool>> filter = null, string includeProperties = null)

		{
			IQueryable<T> query = dbSet;
			if (filter != null)
			{
				query = query.Where(filter);
			}

			if (includeProperties != null)
			{
				foreach (var includeProp in includeProperties.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
				{
					query = query.Include(includeProp);
				}
			}


			return await query.FirstOrDefaultAsync();
		}

		public async Task Remove(string id)
		{
			T entity = await dbSet.FindAsync(id);
			Remove(entity);
		}

		public void Remove(T entity)
		{
			dbSet.Remove(entity);
		}

		public void RemoveRange(IEnumerable<T> entity)
		{
			dbSet.RemoveRange(entity);
		}
	}
}
