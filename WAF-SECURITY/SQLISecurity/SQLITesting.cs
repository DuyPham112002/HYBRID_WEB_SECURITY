using Dapper;
using Microsoft.Extensions.Caching.Memory;
using NET_SECURITY_DATAACCESS.Dapper;
using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.SQLIModel;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Text.RegularExpressions;
using System.Web;

namespace WAF_SECURITY.SQLISecurity
{
    public class SQLITesting : ISQLITesting
    {
        private IMemoryCache _cache;
        private readonly IDapperContext _dapper;

        public SQLITesting(IDapperContext dapper, IMemoryCache cache)
        {
            _dapper = dapper ?? throw new ArgumentNullException(nameof(dapper));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache)); ;
        }

        //CHECK SQL INJECTION - ESCAPE
        public async Task<SQLIInspect> IsEscapeSQLI(RequestModel request)
        {
            try
            {
                string[] patterns = await GetSQLIPatterns("Sqliescape").ConfigureAwait(false);
                if (patterns != null && patterns.Count() > 0)
                {
                    var acTree = new AhoCorasick.Net.AhoCorasickTree(patterns);
                    if (!string.IsNullOrEmpty(request.QueryString))
                    {
                        bool isQueryViolate = acTree.Contains(HttpUtility.UrlDecode(request.QueryString));
                        if (isQueryViolate) return SQLIInspect.Response(true, 403, "Detection: This Request Has An Escape SQL-Injection Attack!");
                    }
                    if (!string.IsNullOrEmpty(request.Body) && (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")))
                    {
                        var parse = JObject.Parse(request.Body);
                        if (CheckingBodyValue(parse, acTree))
                            return SQLIInspect.Response(true, 403, "Detection: This Request Has An Escape SQL-Injection Attack!");
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Escape Pattern SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //CHECK SQL INJECTION - LOGICAL 
        public async Task<SQLIInspect> IsLogicalOperateSQLI(RequestModel request)
        {
            try
            {
                string[] patterns = await GetSQLIPatterns("Sqlilogical").ConfigureAwait(false);
                if (patterns != null && patterns.Count() > 0)
                {
                    var acTree = new AhoCorasick.Net.AhoCorasickTree(patterns);
                    if (!string.IsNullOrEmpty(request.QueryString))
                    {
                        bool isQueryViolate = acTree.Contains(HttpUtility.UrlDecode(request.QueryString));
                        if (isQueryViolate) return SQLIInspect.Response(true, 403, "Detection: This Request Has An Logical Operation SQL-Injection Attack!");
                    }
                    if (!string.IsNullOrEmpty(request.Body) && (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")))
                    {
                        var parse = JObject.Parse(request.Body);
                        if (CheckingBodyValue(parse, acTree))
                            return SQLIInspect.Response(true, 403, "Detection: This Request Has An Logical Operation SQL-Injection Attack!");
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Logical Pattern SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //<!--CHECK SIGNATIRE-BASED SQL INJECTION-->
        //CHECK SQL INJECTION - DEFAULT PATTERN - SIGNATURE BASED
        public async Task<SQLIInspect> IsDefaultPatternSBSQLI(RequestModel request)
        {
            try
            {
                string[] patterns = await GetSQLIPatterns("Sqlidefault").ConfigureAwait(false);
                if (patterns != null && patterns.Count() > 0)
                {
                    var acTree = new AhoCorasick.Net.AhoCorasickTree(patterns);
                    if (!string.IsNullOrEmpty(request.QueryString))
                    {
                        bool isQueryViolate = acTree.Contains(HttpUtility.UrlDecode(request.QueryString));
                        if (isQueryViolate) return SQLIInspect.Response(true, 403, "Detection: This Request Violates Signature Pattern Default SQL-Injection!");
                    }
                    if (!string.IsNullOrEmpty(request.Body) && (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")))
                    {
                        var parse = JObject.Parse(request.Body);
                        if (CheckingBodyValue(parse, acTree))
                            return SQLIInspect.Response(true, 403, "Detection: This Request Violates Signature Pattern Default SQL-Injection!");
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Default Pattern SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //CHECK SQL INJECTION REGULAR EXPRESSION - SIGNATURE BASED
        public async Task<SQLIInspect> IsRExpressionSBSQLI(RequestModel request)
        {
            try
            {
                string[] regulars = await GetSQLIRegularExpressions().ConfigureAwait(false);
                if (regulars != null)
                {
                    //CancellationTokenSource is an object that signals cancellation requests
                    var cancellationTokenSource = new CancellationTokenSource();
                    var cancellationToken = cancellationTokenSource.Token;

                    //This method queues the specified work to run on the thread pool and returns a task representing that work.
                    var tasks = regulars.Select(rx => Task.Run(() =>
                    {
                        if (!string.IsNullOrEmpty(request.QueryString))
                            if (Regex.IsMatch(HttpUtility.UrlDecode(request.QueryString), rx, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            {
                                cancellationTokenSource.Cancel();
                                return true;
                            }
                        if (!string.IsNullOrEmpty(request.Body) && (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")))
                        {
                            var parse = JObject.Parse(request.Body);
                            if (CheckingBodyRX(parse, rx))
                            {
                                cancellationTokenSource.Cancel();
                                return true;
                            }
                        }
                        return false;
                    }, cancellationToken)).ToArray();
                    try
                    {
                        //Wait all task complete and return
                        await Task.WhenAll(tasks).ConfigureAwait(false);
                        if (tasks.Any(t => t.IsCompletedSuccessfully && t.Result))
                        {
                            return SQLIInspect.Response(true, 403, "Detection: This Request Violates Signature Pattern Regular Expression SQL-Injection!");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        return SQLIInspect.Response(true, 403, "Detection: This Request Violates Signature Pattern Regular Expression SQL-Injection!");
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Signature Pattern Regular Expression SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //CHECK SQL INJECTION - RULE CRS - SIGNATURE BASED
        public async Task<SQLIInspect> IsCRSRuleSBSQLI(RequestModel request)
        {
            try
            {
                string coditionLikes = GetCoditionCRS(request);
                SQLIRuleModel[] rules = await GetSQLIRules("SqliRuleCRS", coditionLikes).ConfigureAwait(false);
                if (rules != null)
                {
                    //CancellationTokenSource is an object that signals cancellation requests
                    var cancellationTokenSource = new CancellationTokenSource();
                    var cancellationToken = cancellationTokenSource.Token;

                    //This method queues the specified work to run on the thread pool and returns a task representing that work.
                    var tasks = rules.Select(rule => Task.Run(() =>
                    {
                        if (IsMatch(request, rule))
                        {
                            cancellationTokenSource.Cancel();
                            return true;
                        }
                        return false;
                    }, cancellationToken)).ToArray();
                    try
                    {
                        //Wait all task complete and return
                        await Task.WhenAll(tasks).ConfigureAwait(false);
                        if (tasks.Any(t => t.IsCompletedSuccessfully && t.Result))
                        {
                            return SQLIInspect.Response(true, 403, "Detection: This Request Violates Rule CRS SQL-Injection!");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        return SQLIInspect.Response(true, 403, "Detection: This Request Violates Rule CRS SQL-Injection!");
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Rule CRS SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //<!--CUSTOM RULE-->
        //CHECK SQL INJECTION - RULE CUSTOM
        public async Task<SQLIInspect> IsCTRuleSBSQLI(RequestModel request)
        {
            try
            {
                string coditionLikes = GetCoditionCRS(request);
                SQLIRuleModel[] rules = await GetSQLIRules("SqliRuleCustom", coditionLikes).ConfigureAwait(false);
                if (rules != null)
                {
                    if (rules.Count() > 0)
                    {
                        //CancellationTokenSource is an object that signals cancellation requests
                        var cancellationTokenSource = new CancellationTokenSource();
                        var cancellationToken = cancellationTokenSource.Token;

                        //This method queues the specified work to run on the thread pool and returns a task representing that work.
                        var tasks = rules.Select(rule => Task.Run(() =>
                        {
                            if (IsMatch(request, rule))
                            {
                                cancellationTokenSource.Cancel();
                                return true;
                            }
                            return false;
                        }, cancellationToken)).ToArray();
                        try
                        {
                            //Wait all task complete and return
                            await Task.WhenAll(tasks).ConfigureAwait(false);
                            if (tasks.Any(t => t.IsCompletedSuccessfully && t.Result))
                            {
                                return SQLIInspect.Response(true, 403, "Detection: This Request Violates Rule Custom SQL-Injection!");
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            return SQLIInspect.Response(true, 403, "Detection: This Request Violates Rule Custom SQL-Injection!");
                        }
                    }
                }
                else
                    return SQLIInspect.Response(true, 500, "Get Rule Custom SQL-Injection - Failed!");
                return SQLIInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return SQLIInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //GET ESCAPE-LOGICAL-DEFAULT PATTERN SQL INJECTION PATTERN
        private async Task<string[]> GetSQLIPatterns(string table)
        {
            //Get Cache Memory
            if (_cache.TryGetValue($"Get{table}Patterns", out string[]? patterns))
            {
                if (patterns != null)
                    return patterns;
            }
            using (var conection = _dapper.CreateConnection())
            {
                string[] array = null;
                try
                {
                    string query = $"SELECT Id, Pattern FROM {table}";
                    var result = await conection.QueryAsync<SQLIPatternModel>(query);
                    if (result != null)
                    {
                        array = result.Select(e => e.Pattern).ToArray();
                        //Set Cache Memory
                        SetCacheMemmory<string[]>($"Get{table}Patterns", array);
                    }
                }
                catch (Exception ex)
                {                
                    _cache.Remove($"Get{table}Patterns");
                }
                return array;
            }
        }
        //GET REGULAR EXPRESSION SQL INJECTION
        private async Task<string[]> GetSQLIRegularExpressions()
        {
            //Get Cache Memory
            if (_cache.TryGetValue($"GetRegularExpressions", out string[]? regulars))
            {
                if (regulars != null && regulars != Array.Empty<string>())
                    return regulars;
            }
            using (var conection = _dapper.CreateConnection())
            {
                string[] array = null;
                string query = "SELECT S.Id, S.Pattern FROM SqliRExpression as S join SqliRExpressionConfig crc on S.Level <= crc.\"Level\" and crc.IsActive = 1";
                try
                {
                    var results = await conection.QueryAsync<SQLIRegularExpression>(query);
                    if (results != null)
                    {
                        array = results.Select(e => e.Pattern).ToArray();
                        //Set Cache Memory
                        SetCacheMemmory<string[]>("GetRegularExpressions", array);
                    }
                }
                catch (Exception ex)
                {
                    _cache.Remove("GetRegularExpressions");
                }
                return array;
            }
        }
        //GET CRS SQL INJECTION RULE
        private async Task<SQLIRuleModel[]> GetSQLIRules(string table, string coditionLikes)
        {
            string query = $"SELECT S.Id, S.Pattern, S.Message, S.\"Ignore\", S.Target, S.\"Level\", S.\"Type\", S.Transformation FROM {table} as S join SqliruleConFig crc on S.Level <= crc.\"Level\" and crc.IsActive = 1 where {coditionLikes}";
            //Get Cache Memory
            if (_cache.TryGetValue(query, out IEnumerable<SQLIRuleModel>? cachedRules))
            {
                if (cachedRules != null && cachedRules != Array.Empty<SQLIRuleModel>())
                    return cachedRules.ToArray();
            }
            using (var conection = _dapper.CreateConnection())
            {
                IEnumerable<SQLIRuleModel> results = Array.Empty<SQLIRuleModel>();
                try
                {
                    results = await conection.QueryAsync<SQLIRuleModel>(query);
                    if (results != null)
                    {
                        foreach (var p in results)
                        {
                            p.Targets = SplitAndTrim(p.Target);
                            p.Transformations = SplitAndTrim(p.Transformation);
                        }
                        //Set Cache Memory
                        SetCacheMemmory<IEnumerable<SQLIRuleModel>>(query, results);
                    }    
                }
                catch (Exception ex)
                {
                    results = null;
                    _cache.Remove(query);
                }
                return results.ToArray();
            }
        }
        private string[] SplitAndTrim(string input)
        {
            return input != string.Empty ? input.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToArray() : Array.Empty<string>();
        }

        //CRS RULE CHEKING METHOD
        private bool IsMatch(RequestModel request, SQLIRuleModel rx)
        {
            if (rx.Targets != null && rx.Targets.Count() > 0)
                foreach (var target in rx.Targets)
                {
                    switch (target)
                    {
                        case "AUTH_TYPE":
                            if (CheckRequestAuth(request, rx)) return true;
                            break;

                        case "REQUEST_COOKIES":
                            if (CheckRequestCookies(request, rx)) return true;
                            break;

                        case "REQUEST_COOKIES_NAMES":
                            if (CheckRequestCookiesNames(request, rx)) return true;
                            break;

                        case "REQUEST_HEADERS_NAMES":
                            if (CheckRequestHeadersNames(request, rx)) return true;
                            break;

                        case string t when t.StartsWith("REQUEST_HEADERS"):
                            if (CheckRequestHeaders(request, rx, target)) return true;
                            break;

                        case "REQUEST_BODY" when (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")):
                            if (CheckJsonBody(request, rx)) return true;
                            break;

                        case "REQUEST_METHOD":
                            if (CheckRequestMethod(request, rx)) return true;
                            break;

                        case "REQUEST_PROTOCOL":
                            if (CheckRequestProtocol(request, rx)) return true;
                            break;

                        case "REQUEST_URI":
                            if (CheckRequestUri(request, rx)) return true;
                            break;

                        case "ARGS":
                            if (CheckArgs(request, rx)) return true;
                            break;

                        case "ARGS_NAMES":
                            if (CheckArgsNames(request, rx)) return true;
                            break;

                        case string t when t.StartsWith("ARGS_GET"):
                            if (CheckArgsGet(request, rx, target))
                                return true;
                            break;

                        case "REQUEST_BASENAME":
                            if (CheckRequestBasename(request, rx)) return true;
                            break;

                        case "REQUEST_FILENAME":
                            if (CheckRequestFilename(request, rx)) return true;
                            break;
                    }
                }
            return false;
        }
        //REQUEST_AUTH_TYPE
        private bool CheckRequestAuth(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Headers != null && request.Headers.TryGetValue("Authorization", out string? authHeader))
                if (authHeader != string.Empty)
                {
                    string text = TransformationText(authHeader, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                        return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                    else
                        return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
                }
            return false;
        }
        //REQUEST_COOKIES
        private bool CheckRequestCookies(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Cookies != null && request.Cookies.Any())
            {
                var ignoreList = rx.Ignore?.Split(",") ?? Array.Empty<string>();
                foreach (var cookie in request.Cookies)
                    if (!ignoreList.Any(p => cookie.Key.StartsWith(p)))
                    {
                        string text = TransformationText(cookie.Value, rx.Transformations);
                        if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                        {
                            if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                return true;
                        }
                        else
                        {
                            if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
            }
            return false;
        }
        //REQUEST_COOKIES_NAMES
        private bool CheckRequestCookiesNames(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Cookies != null && request.Cookies.Any())
                foreach (var cookie in request.Cookies)
                {
                    string text = TransformationText(cookie.Key, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            return true;
                    }
                    else
                    {
                        if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            return false;
        }
        //REQUEST_HEADERS
        private bool CheckRequestHeaders(RequestModel request, SQLIRuleModel rx, string target)
        {
            if (request.Headers != null && request.Headers.Count() > 0)
                if (target.Contains(":"))
                {
                    var headerKey = target.Split(':')[1];
                    if (request.Headers.TryGetValue(headerKey, out var headerValue))
                    {
                        string text = TransformationText(headerValue, rx.Transformations);
                        if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                            return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                        else
                            return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
                    }
                }
                else
                {
                    foreach (var header in request.Headers)
                    {
                        string text = TransformationText(header.Value, rx.Transformations);
                        if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                        {
                            if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                                return true;
                        }
                        else
                         if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            return false;
        }
        //REQUEST_HEADERS_NAMES
        private bool CheckRequestHeadersNames(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Headers != null && request.Headers.Count() > 0)
                foreach (var header in request.Headers)
                {
                    string text = TransformationText(header.Key, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            return true;
                    }
                    else
                    {
                        if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            return false;
        }
        //REQUEST_METHOD
        private bool CheckRequestMethod(RequestModel request, SQLIRuleModel rx)
        {
            if (!string.IsNullOrEmpty(request.Method))
            {
                string text = TransformationText(request.Method, rx.Transformations);
                if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                else
                    return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        //REQUEST_PROTOCOL
        private bool CheckRequestProtocol(RequestModel request, SQLIRuleModel rx)
        {
            if (!string.IsNullOrEmpty(request.Protocol))
            {
                string text = TransformationText(request.Protocol, rx.Transformations);
                if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                else
                    return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        //REQUEST_URI
        private bool CheckRequestUri(RequestModel request, SQLIRuleModel rx)
        {
            if (!string.IsNullOrEmpty(request.Path) && !string.IsNullOrEmpty(request.QueryString))
            {
                string uri = TransformationText(request.Path + request.QueryString, rx.Transformations);
                if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    return Regex.IsMatch(uri, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                else
                    return uri.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        //ARGS_NAMES
        private bool CheckArgsNames(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Queries != null && request.Queries.Count() > 0)
                foreach (var query in request.Queries)
                {
                    string text = TransformationText(query.Key, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            return true;
                    }
                    else
                    {
                        if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            return false;
        }
        //ARGS
        private bool CheckArgs(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Queries != null && request.Queries.Count() > 0)
                foreach (var query in request.Queries)
                {
                    string text = TransformationText(query.Value, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            return true;
                    }
                    else
                    {
                        if (text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            return false;
        }
        //ARGS_GET
        private bool CheckArgsGet(RequestModel request, SQLIRuleModel rx, string target)
        {
            if (target.Contains(":"))
            {
                var paramName = target.Split(':').Length >= 1 ? target.Split(':')[1] : string.Empty;
                if (request.Queries != null && request.Queries.Count() > 0 && request.Queries.ContainsKey(paramName))
                {
                    var paramValue = request.Queries[paramName];
                    string text = TransformationText(paramValue, rx.Transformations);
                    if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                        return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                    else
                        return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
                }
            }
            else
                return CheckArgs(request, rx);
            return false;
        }
        //REQUEST_BODY
        private bool CheckJsonBody(RequestModel request, SQLIRuleModel rx)
        {
            if (request.ContentLength > 0 && request.Body != string.Empty && request.ContentType.Contains("json"))
            {
                string text = TransformationText(request.Body, rx.Transformations);
                if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                    return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                else
                    return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        //REQUEST_BASENAME 
        private bool CheckRequestBasename(RequestModel request, SQLIRuleModel rx)
        {
            if (request.Path == string.Empty) return false;
            string text = TransformationText(request.Path, rx.Transformations);
            if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
            else
                return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
        }
        //REQUEST_FILENAME
        private bool CheckRequestFilename(RequestModel request, SQLIRuleModel rx)
        {
            string filename = System.IO.Path.GetFileName(request.Path);
            if (filename == string.Empty) return false;
            string text = TransformationText(filename, rx.Transformations);
            if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
            else
                return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
        }
        //GET BASE LINE CODITION RULE CRS
        private string GetCoditionCRS(RequestModel request)
        {
            var conditions = new List<string>();

            if (request.Headers.TryGetValue("Authorization", out string? text))
                if (!string.IsNullOrEmpty(text))
                    conditions.Add("AUTH_TYPE");

            if (request.Cookies?.Any() == true)
                conditions.Add("REQUEST_COOKIES");

            if (request.Headers?.Any() == true)
                conditions.Add("REQUEST_HEADERS");

            if (request.Queries?.Any() == true)
                conditions.Add("ARGS");

            if (!string.IsNullOrEmpty(request.Body))
                conditions.Add("REQUEST_BODY");

            if (!string.IsNullOrEmpty(request.Method))
                conditions.Add("REQUEST_METHOD");

            if (!string.IsNullOrEmpty(request.Protocol))
                conditions.Add("REQUEST_PROTOCOL");

            if (!string.IsNullOrEmpty(request.Path))
            {
                if (!string.IsNullOrEmpty(request.QueryString))
                    conditions.Add("REQUEST_URI");
                conditions.Add("REQUEST_BASENAME");
                conditions.Add("REQUEST_FILENAME");
            }

            var likeConditions = conditions.Select(param => $"Target LIKE '%{param}%'");
            return string.Join(" OR ", likeConditions);
        }
        //VALIDATE BODY - PATTERN
        private bool CheckingBodyValue(JToken token, AhoCorasick.Net.AhoCorasickTree actree)
        {
            var stack = new Stack<JToken>();
            stack.Push(token);
            while (stack.Count > 0)
            {
                var currentToken = stack.Pop();
                switch (currentToken)
                {
                    case JValue value:
                        if (actree.Contains(value.ToString()))
                            return true;
                        break;

                    case JObject obj:
                        foreach (var property in obj.Properties())
                            stack.Push(property.Value);
                        break;

                    case JArray array:
                        foreach (var item in array)
                            stack.Push(item);
                        break;
                }
            }
            return false;
        }
        //VALIDATE BODY - REGULAR EXPRESSION
        private bool CheckingBodyRX(JToken token, string rx)
        {
            var stack = new Stack<JToken>();
            stack.Push(token);
            while (stack.Count > 0)
            {
                var currentToken = stack.Pop();
                switch (currentToken)
                {
                    case JValue value:
                        if (Regex.IsMatch(value.ToString(), rx, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                            return true;
                        break;

                    case JObject obj:
                        foreach (var property in obj.Properties())
                            stack.Push(property.Value);
                        break;

                    case JArray array:
                        foreach (var item in array)
                            stack.Push(item);
                        break;
                }
            }
            return false;
        }
        //TRANSFORMATION STRING
        private string TransformationText(string input, string[] transfors)
        {
            if (transfors == Array.Empty<string>())
            {
                Dictionary<string, Action> transformations = new Dictionary<string, Action>(StringComparer.OrdinalIgnoreCase)
                {
                    { "t:trim", () => input = input.Trim() },
                    { "t:lowercase", () => input = input.ToLowerInvariant() },
                    { "t:urlDecode", () => input = HttpUtility.UrlDecode(input) }
                };
                foreach (var item in transfors)
                    if (transformations.TryGetValue(item, out Action action))
                        action.Invoke();
            }
            return input;
        }
        //SET CACHE MEMMORY
        private void SetCacheMemmory<T>(string key, T data)
        {
            var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromMinutes(5))
                    .SetAbsoluteExpiration(TimeSpan.FromMinutes(30))
                    .SetPriority(CacheItemPriority.Normal);
            //.SetSize(1024);
            _cache.Set(key, data, cacheEntryOptions);
        }
    }
}