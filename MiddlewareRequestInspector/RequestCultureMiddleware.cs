using Google.Protobuf.Collections;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.AspNetCore.Http;
using RequestCultureMiddleware.Model;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Builder;
using System.Net.Mime;
using RequestCultureMiddleware.Service;

namespace RequestCultureMiddleware
{
    public class RequestCultureMiddleware
    {
        private readonly RequestDelegate _next;
        //private HttpClient _httpClient;
        private readonly IGrpcServiceClient _grpc;
        public RequestCultureMiddleware(RequestDelegate next, IGrpcServiceClient grpc)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _grpc = grpc ?? throw new ArgumentNullException(nameof(grpc));
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!IsValidRequest(context.Request))
            {
                await _next(context);
                return;
            }
    
            var grpcMessage = await CreateGrpcMessage(context.Request);
            try
            {
                var checkPacket = await _grpc.VerifiedRequestAsync(grpcMessage);
                if (checkPacket.IsSecurity)
                {
                    await _next(context);
                    return;
                }
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(CreateProblemDetails(context, checkPacket.StatusCode, checkPacket.Message)));
            }
            catch (Exception ex)
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(CreateProblemDetails(context, StatusCodes.Status500InternalServerError, ex.Message)));
            }
        }

        private bool IsValidRequest(HttpRequest request)
        {
            return request == null || (request.QueryString.Value == string.Empty && (request.ContentLength == null || request.ContentLength == 0)) ? false : true;
        }

        private async Task<RequestMessage> CreateGrpcMessage(HttpRequest request)
        {
            var grpcMessage = new RequestMessage
            {
                Method = request.Method,
                Path = request.Path,
                Protocol = request.Protocol,
                QueryString = request.QueryString.Value,
                ContentType = request.ContentType,
                ContentLength = request.ContentLength,
                Queries = request.Query.ToDictionary(h => h.Key, h => h.Value.ToString()),
                Headers = request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                Cookies = request.Cookies.ToDictionary(h => h.Key, h => h.Value.ToString())
            };

            if (request.Method == HttpMethods.Post)
            {
                if (request.HasFormContentType)
                {
                    grpcMessage.Body = ReadRequestBody(request).Result;
                }

                if (request.HasFormContentType)
                {
                    grpcMessage.HasFormContentType = true;
                    grpcMessage.Files = await GetFilesFromFormAsync(request);
                }
            }

            return grpcMessage;
        }

        private async Task<string> ReadRequestBody(HttpRequest request)
        {
            request.EnableBuffering();
            using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            request.Body.Position = 0;
            return body;
        }

        private async Task<RepeatedField<FileRequest>> GetFilesFromFormAsync(HttpRequest request)
        {
            var fileRequests = new RepeatedField<FileRequest>();
            var formCollection = await request.ReadFormAsync();

            foreach (var file in formCollection.Files)
            {
                if (file != null)
                {
                    using var memoryStream = new MemoryStream();
                    await file.CopyToAsync(memoryStream);

                    fileRequests.Add(new FileRequest
                    {
                        Length = file.Length,
                        Headers = file.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                        FileContent = memoryStream.ToArray(),
                        FileName = file.FileName
                    });
                }
            }
            return fileRequests;
        }
        private ProblemDetails CreateProblemDetails(HttpContext context, int status, string exception)
        {
            var traceId = Guid.NewGuid();
            context.Response.StatusCode = status;
            return new ProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc7231#section-6.6.1",
                Title = ReasonPhrases.GetReasonPhrase(status),
                Status = status,
                Detail = $"TraceId: {traceId}, Error: {exception}"
            };
        }
    }
    public static class RequestCultureMiddlewareExtensions
    {
        public static IApplicationBuilder UseRequestCulture(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<RequestCultureMiddleware>();
        }
    }
}
