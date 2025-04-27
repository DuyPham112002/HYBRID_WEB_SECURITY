using System.Linq.Expressions; // Thư viện cho phép tạo các biểu thức lambda (lambda expressions) dùng để xây dựng các truy vấn linh động.

namespace NET_SECURITY_DATAACCESS.Repository.Base // Định nghĩa một không gian tên chứa các lớp và interface cơ bản của repository.
{
    /// <summary>
    /// Định nghĩa một interface tổng quát cho các thao tác CRUD cơ bản.
    /// </summary>
    /// <typeparam name="T">Kiểu dữ liệu của thực thể, phải là một lớp.</typeparam>
    public interface IRepository<T> where T : class
    {
        /// <summary>
        /// Lấy một thực thể theo ID (bất đồng bộ).
        /// </summary>
        /// <param name="id">ID của thực thể cần lấy.</param>
        /// <returns>Thực thể có ID tương ứng.</returns>
        Task<T> GetAsync(string id);

        /// <summary>
        /// Lấy danh sách tất cả các thực thể thoả mãn điều kiện lọc (nếu có), có thể sắp xếp và bao gồm các thuộc tính liên quan (bất đồng bộ).
        /// </summary>
        /// <param name="filter">Điều kiện lọc dưới dạng biểu thức lambda (tuỳ chọn).</param>
        /// <param name="orderBy">Hàm sắp xếp dữ liệu (tuỳ chọn).</param>
        /// <param name="includeProperties">Danh sách các thuộc tính liên quan cần bao gồm (tuỳ chọn).</param>
        /// <returns>Danh sách các thực thể thoả mãn điều kiện.</returns>
        Task<List<T>> GetAllAsync(Expression<Func<T, bool>> filter = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            string includeProperties = null);

        /// <summary>
        /// Lấy thực thể đầu tiên thoả mãn điều kiện lọc (nếu có) và bao gồm các thuộc tính liên quan (bất đồng bộ).
        /// </summary>
        /// <param name="filter">Điều kiện lọc dưới dạng biểu thức lambda (tuỳ chọn).</param>
        /// <param name="includeProperties">Danh sách các thuộc tính liên quan cần bao gồm (tuỳ chọn).</param>
        /// <returns>Thực thể đầu tiên thoả mãn điều kiện.</returns>
        Task<T> GetFirstOrDefaultAsync(Expression<Func<T, bool>> filter = null,
            string includeProperties = null);

        /// <summary>
        /// Thêm một thực thể mới vào cơ sở dữ liệu (bất đồng bộ).
        /// </summary>
        /// <param name="entity">Thực thể cần thêm.</param>
        /// <returns>Một tác vụ bất đồng bộ.</returns>
        Task AddAsync(T entity);

        /// <summary>
        /// Xoá một thực thể khỏi cơ sở dữ liệu theo ID (bất đồng bộ).
        /// </summary>
        /// <param name="id">ID của thực thể cần xoá.</param>
        /// <returns>Một tác vụ bất đồng bộ.</returns>
        Task Remove(string id);

        /// <summary>
        /// Xoá một thực thể khỏi cơ sở dữ liệu.
        /// </summary>
        /// <param name="entity">Thực thể cần xoá.</param>
        void Remove(T entity);

        /// <summary>
        /// Xoá nhiều thực thể khỏi cơ sở dữ liệu.
        /// </summary>
        /// <param name="entity">Danh sách các thực thể cần xoá.</param>
        void RemoveRange(IEnumerable<T> entity);
    }
}
