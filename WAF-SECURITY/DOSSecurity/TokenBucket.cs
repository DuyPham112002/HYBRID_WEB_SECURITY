using NET_SECURITY_MODEL.DOSModel;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAF_SECURITY.DOSSecurity
{
    public class TokenBucket : ITokenBucket
    {
        private BlockingCollection<Token> _tokens;
        private System.Timers.Timer _timer;
        private int _maxTokens;
        public TokenBucket(int maxNumberOfTokens, int refillRateInMilliseconds)
        {
            _maxTokens = maxNumberOfTokens;
            _timer = new System.Timers.Timer(refillRateInMilliseconds);
            _tokens = new BlockingCollection<Token>(maxNumberOfTokens);
            Init(maxNumberOfTokens);
        }

        public DOSInspect UseToken()
        {
            try
            {
                if (!_tokens.TryTake(out Token? _))
                {
                    return DOSInspect.Response(true, 429, "Too Many Requests To Process In The System Time Allowed!");
                }
                return DOSInspect.Response(false, 204);
            }catch(Exception ex)
            {
                return DOSInspect.Response(false, 500, ex.Message.ToString());
            }
        }

        private void Init(int maxNumberOfTokens)
        {
            foreach (var _ in Enumerable.Range(0, maxNumberOfTokens))
                _tokens.Add(new Token());

            _timer.AutoReset = true;
            _timer.Enabled = true;
            _timer.Elapsed += OnTimerElapsed;
        }

        private void OnTimerElapsed(object? sender, System.Timers.ElapsedEventArgs e)
        {
            foreach (var _ in Enumerable.Range(0, _maxTokens - _tokens.Count))
                _tokens.Add(new Token());
        }
    }
    public record Token;
}
