using Dapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using NET_SECURITY_DATAACCESS.Dapper;
using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.SQLIModel;
using NET_SECURITY_MODEL.XSSModel;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using WAF_SECURITY.DOSSecurity;
using WAF_SECURITY.SQLISecurity;

namespace WAF_SECURITY.XSSSecurity
{
    public class XSSTesting : IXSSTesting
    {
        private readonly IDapperContext _dapper;
        private IMemoryCache _cache;

        public XSSTesting(IDapperContext dapper, IMemoryCache cache)
        {
            _dapper = dapper ?? throw new ArgumentNullException(nameof(dapper));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache)); ;
        }

        //<!--CHECK SIGNATIRE-BASED XSS-->
        public async Task<XSSInspect> IsDefaultPatternSBSXSS(RequestModel request)
        {
            if (request == null) return XSSInspect.Response(true, 500, "REQUEST CONVERT NULL!");
            try
            {
                string[] patterns = await GetXSSPatterns("XssDefault").ConfigureAwait(false);
                if (patterns != null)
                {
                    var acTree = new AhoCorasick.Net.AhoCorasickTree(patterns);
                    if (!string.IsNullOrEmpty(request.QueryString))
                    {
                        bool isQueryViolate = acTree.Contains(HttpUtility.UrlDecode(request.QueryString));
                        if (isQueryViolate) return XSSInspect.Response(true, 403, "Detection: This Request Violates XSS-Default Pattern!");
                    }
                    if (!string.IsNullOrEmpty(request.Body) && (string.Equals(request.Method, "POST") || string.Equals(request.Method, "PUT") || string.Equals(request.Method, "PATCH")))
                    {
                        var parse = JObject.Parse(request.Body);
                        if (CheckingBodyValue(parse, acTree))
                            return XSSInspect.Response(true, 403, "Detection: This Request Violates XSS-Default Pattern!");
                    }
                }
                else
                    return XSSInspect.Response(true, 500, "Get Default Pattern XSS - Failed!");
                return XSSInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return XSSInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //<!--CHECK RULE CRS XSS-->
        public async Task<XSSInspect> IsCRSRuleSBSXSS(RequestModel request)
        {
            if (request == null) return XSSInspect.Response(true, 500, "REQUEST CONVERT NULL!");
            try
            {
                string coditionLikes = GetCoditionCRS(request);
                XSSRuleModel[] rules = await GetXSSRules("XssRuleCRS", coditionLikes).ConfigureAwait(false);
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
                            return XSSInspect.Response(true, 403, "Detection: This Request Violates Rule CRS XSS!");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        return XSSInspect.Response(true, 403, "Detection: This Request Violates Rule CRS XSS!");
                    }
                }
                else
                    return XSSInspect.Response(true, 500, "Get Rule CRS XSS - Failed!");
                return XSSInspect.Response(false, 204);
            }
            catch (Exception ex)
            {
                return XSSInspect.Response(true, 500, ex.Message.ToString());
            }
        }
        //GET BASE LINE CODITION RULE CRS
        private string GetCoditionCRS(RequestModel request)
        {
            var conditions = new List<string>();

            if (request.Cookies?.Any() == true)
                conditions.Add("REQUEST_COOKIES");

            if (request.Headers?.Any() == true)
                conditions.Add("REQUEST_HEADERS");

            if (request.Queries?.Any() == true)
                conditions.Add("ARGS");

            if (!string.IsNullOrEmpty(request.Method))
                conditions.Add("REQUEST_METHOD");

            if (!string.IsNullOrEmpty(request.Protocol))
                conditions.Add("REQUEST_PROTOCOL");

            if (!string.IsNullOrEmpty(request.Path))
            {
                if (!string.IsNullOrEmpty(request.QueryString))
                    conditions.Add("REQUEST_FILENAME");
            }

            var likeConditions = conditions.Select(param => $"Target LIKE '%{param}%'");
            return string.Join(" OR ", likeConditions);
        }

        //GET CRS XSS RULE
        private async Task<XSSRuleModel[]> GetXSSRules(string table, string coditionLikes)
        {
            string query = $"SELECT S.Id, S.Pattern, S.Message, S.\"Ignore\", S.Target, S.\"Level\", S.\"Type\", S.Transformation FROM {table} as S join XssruleConFig crc on S.Level <= crc.\"Level\" and crc.IsActive = 1 where {coditionLikes}";
            ////Get Cache Memory
            //if (_cache.TryGetValue(query, out IEnumerable<XSSRuleModel>? cachedRules))
            //{
            //    if (cachedRules != null && cachedRules != Array.Empty<XSSRuleModel>())
            //        return cachedRules.ToArray();
            //}
            using (var conection = _dapper.CreateConnection())
            {
                IEnumerable<XSSRuleModel> results = Array.Empty<XSSRuleModel>();
                try
                {
                    results = await conection.QueryAsync<XSSRuleModel>(query);
                    if (results != null)
                    {
                        foreach (var p in results)
                        {
                            p.Targets = SplitAndTrim(p.Target);
                            p.Transformations = SplitAndTrim(p.Transformation);
                        }
                        //Set Cache Memory
                        SetCacheMemmory<IEnumerable<XSSRuleModel>>(query, results);
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

        //CRS RULE CHEKING METHOD
        private bool IsMatch(RequestModel request, XSSRuleModel rx)
        {
            if (rx.Targets != null && rx.Targets.Count() > 0)
                foreach (var target in rx.Targets)
                {
                    switch (target)
                    {
                        case "REQUEST_COOKIES":
                            if (CheckRequestCookies(request, rx)) return true;
                            break;

                        case "REQUEST_COOKIES_NAMES":
                            if (CheckRequestCookiesNames(request, rx)) return true;
                            break;

                        case string t when t.StartsWith("REQUEST_HEADERS"):
                            if (CheckRequestHeaders(request, rx, target)) return true;
                            break;

                        case "ARGS":
                            if (CheckArgs(request, rx)) return true;
                            break;

                        case "ARGS_NAMES":
                            if (CheckArgsNames(request, rx)) return true;
                            break;

                        case "REQUEST_FILENAME":
                            if (CheckRequestFilename(request, rx)) return true;
                            break;
                    }
                }
            return false;
        }

        //REQUEST_AUTH_TYPE
        private bool CheckRequestAuth(RequestModel request, XSSRuleModel rx)
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
        private bool CheckRequestCookies(RequestModel request, XSSRuleModel rx)
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
        private bool CheckRequestCookiesNames(RequestModel request, XSSRuleModel rx)
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
        private bool CheckRequestHeaders(RequestModel request, XSSRuleModel rx, string target)
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
        private bool CheckRequestHeadersNames(RequestModel request, XSSRuleModel rx)
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
        private bool CheckRequestMethod(RequestModel request, XSSRuleModel rx)
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

        //ARGS_NAMES
        private bool CheckArgsNames(RequestModel request, XSSRuleModel rx)
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
        private bool CheckArgs(RequestModel request, XSSRuleModel rx)
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
        private bool CheckArgsGet(RequestModel request, XSSRuleModel rx, string target)
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

        //REQUEST_FILENAME
        private bool CheckRequestFilename(RequestModel request, XSSRuleModel rx)
        {
            string filename = System.IO.Path.GetFileName(request.Path);
            if (filename == string.Empty) return false;
            string text = TransformationText(filename, rx.Transformations);
            if (rx.Type.Equals("@rx", StringComparison.OrdinalIgnoreCase))
                return Regex.IsMatch(text, rx.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
            else
                return text.Contains(rx.Pattern, StringComparison.OrdinalIgnoreCase);
        }

        private string[] SplitAndTrim(string input)
        {
            return input != string.Empty ? input.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToArray() : Array.Empty<string>();
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

        //GET DEFAULT PATTERN XSS PATTERN
        private async Task<string[]> GetXSSPatterns(string table)
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

        //TRANSFORMATION STRING
        private List<string> transfors = new List<string> { "t:trim", "t:lowercase", "t:urlDecode" };
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
