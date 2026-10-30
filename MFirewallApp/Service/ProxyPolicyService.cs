using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;

namespace MFirewallApp.Service
{
    public class ProxyPolicyService : IProxyPolicyService
    {
        private readonly IOptionsMonitor<HttpProxyConfiguration> _proxyConfig;
        public ProxyPolicyService(IOptionsMonitor<HttpProxyConfiguration> proxyConfig)
        {
            _proxyConfig = proxyConfig;
        }
        public  async Task<Result<string>> IsAllowedDomain(string? domain)
        {
            if(domain == null)
            {
                return Result<string>.Failure("domain is null");
            }
            var whitelist = _proxyConfig.CurrentValue.AllowedDomainOptions.AllowedDomains;
            var blacklist = _proxyConfig.CurrentValue.BlackListDomainOptions.BlackList;

            if (blacklist.Contains(domain))
            {
                return Result<string>.Failure("Domain found on a blacklist"); //строго
            }

            if (whitelist.Contains("*"))
            {
                return Result<string>.Success;
            }
            if (!whitelist.Contains(domain))
            {
                return Result<string>.Failure("Domain not found on a allowed list");
            }
            return Result<string>.Success;
        }

        public async Task<Result<string>> IsAllowedUrl(string? url)
        {

            if (Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl))
            {
                string query = parsedUrl.Query;
                var parsedParameters = HttpUtility.ParseQueryString(query);
                var forribdenParameters = _proxyConfig.CurrentValue.UrlOptions.NotAllowedQueryParameters;
                bool contains = false;
                string? forribdenParameter ="";
                foreach (var parameter in parsedParameters.AllKeys)
                {
                    if (forribdenParameters.Contains(parameter))
                    {
                        contains = true;
                        forribdenParameter = parameter;

                        break;
                    }
                }

                if (contains)
                {
                    return Result<string>.Failure($"Parameter {forribdenParameter} found on a not allowed query parameters");
                }
                return Result<string>.Success;
            }

            return Result<string>.Failure("Url query parse error");
        }

       
        public async Task<Result<string>> ShouldAccept(HttpRequest request)
        {
            var tasks = new List<Task<Result<string>>>()
            {
                IsAllowedDomain(request.Headers["Host"]),
                IsAllowedUrl(UriHelper.GetDisplayUrl(request))
            };

            var result = await Task.WhenAll(tasks);

            var badChecks = result.Where(r => !r.IsSuccess).ToArray();

            if (badChecks.Length < 1)
            {
                return Result<string>.Success;
            }

            var sb = new StringBuilder();
            
            foreach(var check in badChecks)
            {
                sb.Append(check.Error + "--| ");
            }
           
            return Result<string>.Failure(sb.ToString());
        }
    }
}