using Dapper;
using Google.Protobuf.Collections;
using Microsoft.Extensions.Caching.Memory;
using NET_SECURITY_DATAACCESS.Dapper;
using NET_SECURITY_MODEL.ConfigurationModel;
using NET_SECURITY_MODEL.FileUploadModel;
using NET_SECURITY_MODEL.SQLIModel;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

namespace WAF_SECURITY.FileUploadSecurity
{
    public class FileUploadTesting : IFileUploadTesting
    {
        private IMemoryCache _cache;
        private readonly IDapperContext _dapper;
        private Dictionary<string, List<byte[]>> _fileSignature { get; set; }
        public FileUploadTesting(IDapperContext dapper, IMemoryCache cache)
        {
            _dapper = dapper ?? throw new ArgumentNullException(nameof(dapper));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache)); ;
        }
        //INSPECT FILE EXTENSION UPLOAD FROM REQUEST
        public async Task<FILEInspect> InspectFileExtension(RepeatedField<FileModel> files)
        {
            try
            {
                await GetFileExtensionSignatureData();
                foreach (var file in files)
                {
                    if (_fileSignature == null) FILEInspect.Response(false, 500, "Get File Extension And Signature - Failed!");
                    if (!IsValidFileExtensionAndSignature(file.FileName, file.FileContent))
                        return FILEInspect.Response(false, 400, "The Uploaded File Does Not Have The Correct Signature Extension Format!");
                }
            }
            catch (Exception ex)
            {
                FILEInspect.Response(false, 500, ex.Message.ToString());
            }
            return FILEInspect.Response(true, 204);
        }
        //INSPECT FILE MALWARE UPLOAD FROM REQUEST
        public async Task<FILEInspect> InspectFileMalware(RepeatedField<FileModel> files)
        {
            var cancellationTokenSource = new CancellationTokenSource();
            var cancellationToken = cancellationTokenSource.Token;
            var tasks = files.Select(async file =>
            {
                var tempFilePath = Path.GetTempFileName();
                try
                {
                    using (var stream = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
                    {
                        await stream.WriteAsync(file.FileContent, 0, (int)file.Length);
                    }

                    var scan = await Task.Run(() => RunClamScan(tempFilePath), cancellationToken);
                    if (!scan.IsClean)
                    {
                        cancellationTokenSource.Cancel();
                        return scan;
                    }
                }
                catch (Exception ex)
                {
                    return FILEInspect.Response(false, 500, ex.Message);
                }
                finally
                {
                    if (File.Exists(tempFilePath))
                        File.Delete(tempFilePath);
                }
                return FILEInspect.Response(true, 202);
            });
            var results = await Task.WhenAll(tasks);
            var failedResult = results.FirstOrDefault(r => !r.IsClean);
            if (failedResult != null)
            {
                return failedResult;
            }
            return FILEInspect.Response(true, 204);
        }

        //VERIFY SIGNATURE FILE 
        private bool IsValidFileExtensionAndSignature(string fileName, byte[] data)
        {
            if (string.IsNullOrEmpty(fileName) || data == null || data.Length == 0)
            {
                return false;
            }

            var ext = Path.GetExtension(fileName).ToLowerInvariant();

            if (string.IsNullOrEmpty(ext))
            {
                return false;
            }

            var signatures = _fileSignature[ext];
            var headerBytes = data.Take(signatures.Max(m => m.Length));

            return signatures.Any(signature =>
                headerBytes.Take(signature.Length).SequenceEqual(signature));
        }
        //NEED TO SCAN VIRUS - MALWARE
        private FILEInspect RunClamScan(string filePath)
        {
            var processStartInfo = new ProcessStartInfo
            {
                FileName = "C:\\Strawberry\\perl\\bin\\perl.exe",
                Arguments = $"\"{"E:\\Project Code\\ASP.NET_CORE\\HYBRID_WEB_SECURITY\\NET-GRPC-SECURITY\\Ultil\\AV-Scanning\\runav.pl"}\" \"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            string output;
            string errorOutput;
            using (var process = new Process { StartInfo = processStartInfo })
            {
                try
                {
                    process.Start();
                    output = process.StandardOutput.ReadToEnd();
                    errorOutput = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                }
                catch (Exception ex)
                {
                    return new FILEInspect
                    {
                        IsClean = false,
                        Status = 500,
                        Message = ex.Message.ToString()
                    };
                }
            }
            return ParseClamScanOutput(output);
        }
        //GET NAME OF VIRUS/MALWARE
        private FILEInspect ParseClamScanOutput(string output)
        {
            if (output.Contains("OK"))
            {
                return FILEInspect.Response(true, 204, "OK");
            }
            else if (output.Contains("FOUND"))
            {
                var virusName = Regex.Match(output, @": (.+) FOUND").Groups[1].Value;
                return FILEInspect.Response(false, 400, virusName);
            }
            return FILEInspect.Response(false, 400, output);
        }

        //GET EXTENSION DATA
        private async Task GetFileExtensionSignatureData()
        {
            //Get Cache Memory
            if (_cache.TryGetValue("GetFileExtensionSignatureData", out Dictionary<string, List<byte[]>> FileSignature))
            {
                if (FileSignature != null)
                {
                    _fileSignature = FileSignature;
                    return;
                }
            }
            using (var conection = _dapper.CreateConnection())
            {
                _fileSignature = new Dictionary<string, List<byte[]>>();
                try
                {
                    string query = @"SELECT e.Name as [Extension], s.HexSignature FROM FileExtension e LEFT JOIN FileSignature s ON e.Id = s.ExtensionId;";
                    var result = await conection.QueryAsync<FileExtention, byte[], List<byte[]>>(query,
                        (fileExt, signature) =>
                        {
                            if (!_fileSignature.TryGetValue(fileExt.Extension, out var fileExtension))
                            {
                                fileExtension = new List<byte[]>();
                                _fileSignature.Add(fileExt.Extension, fileExtension);
                            }
                            if (signature != null)
                            {
                                fileExtension.Add(signature);
                            }
                            return fileExtension;
                        },
                    splitOn: "HexSignature");
                    //Set Cache Memory
                    SetCacheMemmory<Dictionary<string, List<byte[]>>>("GetFileExtensionSignatureData", _fileSignature);
                }
                catch (Exception ex)
                {
                    _fileSignature = null;
                    _cache.Remove("GetFileExtensionSignatureData");
                }
            }
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
