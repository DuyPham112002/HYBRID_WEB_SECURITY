using Grpc.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NET_GRPC_SECURITY;
using NET_SECURITY_DATAACCESS.Entities;
using NET_SECURITY_MODEL.ConfigurationModel;
using NET_SECURITY_MODEL.FileUploadModel;
using NET_SECURITY_MODEL.GrpcMessageModel;
using NET_SECURITY_MODEL.SQLIModel;
using NET_SECURITY_MODEL.XSSModel;
using WAF_SECURITY.DOSSecurity;
using WAF_SECURITY.FileUploadSecurity;
using WAF_SECURITY.SQLISecurity;
using WAF_SECURITY.XSSSecurity;
using static Google.Rpc.Context.AttributeContext.Types;

namespace NET_GRPC_SECURITY.Security
{
    public class ProtobufSecurity : Protobuf.ProtobufBase
    {
        private readonly ITokenBucket _token;
        private readonly ISQLITesting _sqls;
        private readonly IXSSTesting _xss;
        private readonly IFileUploadTesting _files;
        public ProtobufSecurity(ITokenBucket token, ISQLITesting sqls, IXSSTesting xss, IFileUploadTesting files)
        {
            _token = token;
            _sqls = sqls;
            _files = files;
            _xss = xss;
        }
        //RECEIVE REQUEST AND SCAN REQUEST (WAF-IDS/IPS-LOG)
        public override async Task<ResponseMessage> RequestVerificationAsync(RequestMessage message, ServerCallContext context)
        {
            //Bind AppConfig From AppSetting To AppConfig Model
            AppConfiguration appConfiguration = context.GetHttpContext().RequestServices.GetRequiredService<AppConfiguration>();
            //Convert Message From Protobuff To Request Model 
            RequestModel request = ConvertMessageToModel(message);
            if (request == null)
                return await Task.FromResult(new ResponseMessage
                {
                    IsSecurity = false,
                    StatusCode = 500,
                    Message = "REQUEST CONVERT NULL!"
                });
            //WAF-Security (First Scan Module)
            var detectResponseWAF = await WAFValidating(request, appConfiguration);
            if (!detectResponseWAF.IsSecurity)
                return detectResponseWAF;
            //IDS/IPS - Security (Second Scan Module)
            //...
            return await Task.FromResult(new ResponseMessage
            {
                IsSecurity = true,
                StatusCode = 204,
                Message = "SAFE REQUEST"
            });
        }
        private RequestModel ConvertMessageToModel(RequestMessage message)
        {
            if (message != null)
            {
                //Convert message -> model
                var request = new RequestModel
                {
                    Method = message.Method,
                    Path = message.Path,
                    Protocol = message.Protocol,
                    QueryString = message.QueryString,
                    ContentLength = message.ContentLength,
                    ContentType = message.ContentType,
                    Headers = message.Headers,
                    Queries = message.Queries,
                    Cookies = message.Cookies,
                    Body = message.Body,
                    HasFormContentType = message.HasFormContentType
                };
                if (message.HasFormContentType && (request.Method == "POST" || request.Method == "PUT" || request.Method == "PATCH"))
                {
                    foreach (var item in message.Files)
                    {
                        request.Files.Add(new FileModel
                        {
                            Headers = item.Headers.ToDictionary(),
                            FileContent = item.FileContent.ToByteArray(),
                            Length = item.Length,
                            FileName = item.FileName
                        });
                    }
                }
                return request;
            }
            return null;
        }
        //WAF - Security
        private async Task<ResponseMessage> WAFValidating(RequestModel request, AppConfiguration appConfig)
        {
            //WAF - Rate Limit Implement 
            if (appConfig.RateLimit.Enabled)
            {
                var result = _token.UseToken();
                if (result.IsDrop)
                    return new ResponseMessage
                    {
                        IsSecurity = false,
                        StatusCode = result.Status,
                        Message = result.Message,
                    };
            }
           
            if (!request.HasFormContentType)
            {
                //WAF - Define Verify Sql Injection
                var checkSQLI = new List<Func<RequestModel, Task<SQLIInspect>>>
                  {
                      _sqls.IsEscapeSQLI,
                      _sqls.IsLogicalOperateSQLI,
                      _sqls.IsDefaultPatternSBSQLI,
                      _sqls.IsRExpressionSBSQLI,
                      _sqls.IsCRSRuleSBSQLI,
                      _sqls.IsCTRuleSBSQLI
                  };
                foreach (var sqlinjection in checkSQLI)
                {
                    var verify = await sqlinjection(request);
                    if (verify.IsViolated)
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message,
                        };
                }
                //WAF - Define Verify Xss 
                var checkXSS = new List<Func<RequestModel, Task<XSSInspect>>>
                  {
                      _xss.IsDefaultPatternSBSXSS,
                      _xss.IsCRSRuleSBSXSS
                  };
                foreach (var xss in checkXSS)
                {
                    var verify = await xss(request);
                    if (verify.IsViolated)
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message,
                        };
                }
            }
            //WAF - Define Verify File Upload
            if (request.HasFormContentType)
            {
                FILEInspect verify = new FILEInspect();
                List<FileModel> files = request.Files.Where(p => appConfig.VerifyType.FileExtensionsNormal.Contains(Path.GetExtension(p.FileName))).ToList();
                if (files != null && files.Any())
                {
                    verify = await _files.InspectFileExtension(request.Files);
                    if (!verify.IsClean)
                        return new ResponseMessage
                        {
                            IsSecurity = false,
                            StatusCode = verify.Status,
                            Message = verify.Message
                        };
                }
                if (appConfig.InspectFile.Enabled)
                {
                    files = new List<FileModel>();
                    files = request.Files.Where(p => appConfig.VerifyType.FileExtensionsToScan.Contains(Path.GetExtension(p.FileName))).ToList();
                    if (files != null && files.Any())
                    {
                        verify = await _files.InspectFileMalware(request.Files);
                        if (!verify.IsClean)
                            return new ResponseMessage
                            {
                                IsSecurity = false,
                                StatusCode = verify.Status,
                                Message = verify.Message
                            };
                    }
                }
            }
            //WAF - Verify Finish
            return await Task.FromResult(new ResponseMessage
            {
                IsSecurity = true,
                StatusCode = 204,
                Message = "WAF - Request No Violation!"
            });
        }
    }
}
