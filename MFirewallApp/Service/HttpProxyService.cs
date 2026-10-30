
using MFirewallApp.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.VisualBasic;


namespace MFirewallApp.Service
{
    public class HttpProxyService : IProxyService
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IProxyPolicyService _proxyPolicyService;

        public HttpProxyService(IHttpContextAccessor contextAccessor,IProxyPolicyService proxyPolicyService)
        {
            _contextAccessor = contextAccessor;
            _proxyPolicyService = proxyPolicyService;
          
        }
        public async Task<Result<string>> ValidateAsync(CancellationToken token)
        {
            var context = _contextAccessor.HttpContext;
       
            if (context is null)
            {
                return Result<string>.Failure("Not found context");
            }
        
            var shouldForward =await _proxyPolicyService.ShouldAccept(context.Request);

            return shouldForward;
        }
       
    }
}