
using Newtonsoft.Json;
using RequestCultureMiddleware.Model;
using System.Text;

namespace RequestCultureMiddleware.Service
{
    public interface IGrpcServiceClient
    {
        Task<ResponseBase> VerifiedRequestAsync(RequestMessage request);
    }
    public class GrpcServiceClient : IGrpcServiceClient
    {
        private readonly HttpClient _httpClient;
        public GrpcServiceClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }
        public async Task<ResponseBase> VerifiedRequestAsync(RequestMessage request)
        {
            try
            {
                var json = JsonConvert.SerializeObject(request);
                var content = new StringContent(json.ToString(), Encoding.UTF8, "application/json");

               HttpResponseMessage response = await _httpClient.PostAsync("/v1/RequestVerify", content);
                if (response.IsSuccessStatusCode)
                {
                    string text = await response.Content.ReadAsStringAsync();
                    var responsebase = JsonConvert.DeserializeObject<ResponseBase>(text);
                    return responsebase;
                }
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message.ToString());
                return null;
            }
        }
    }
}
