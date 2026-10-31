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
        private async Task<Result<string>> NotContainsBlockedExtension(string url)
        {
            var blockedExtensions = _proxyConfig.CurrentValue.UrlOptions.BlockedExtensions;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl))
            {
                return Result<string>.Failure("Url parse error");
            }

            var extension = Path.GetExtension(parsedUrl.AbsolutePath);
             System.Console.WriteLine($"extension = {extension}");

            if (string.IsNullOrWhiteSpace(extension))
            {
                return Result<string>.Success;
            }
           
            var blockedExtension = blockedExtensions.FirstOrDefault(e => extension.Equals(e, StringComparison.OrdinalIgnoreCase));

            if (blockedExtension != null)
            {
                return Result<string>.Failure($"File extension {blockedExtension} is blocked");
            }

            return Result<string>.Success;
        }
        private async Task<Result<string>> NotContainsBlockedKeyWords(string url)
        {
            var blockedKeywords = _proxyConfig.CurrentValue.UrlOptions.NotAllowedKeyWords;

            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl))
            {
                return Result<string>.Failure("Url parse error");
            }
            var textToCheck = Uri.UnescapeDataString(parsedUrl.PathAndQuery);
            var blockedKeyword = blockedKeywords
            .FirstOrDefault(k => !string.IsNullOrEmpty(k)
            && textToCheck.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (blockedKeyword != null)
            {
                return Result<string>.Failure($"Blocked keyword {blockedKeyword} found in URL");
            }
            return Result<string>.Success;

        }
        private  async Task<Result<string>> IsAllowedDomain(string? domain)
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

        private async Task<Result<string>> IsAllowedUrl(string? url)
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
                IsAllowedDomain(request.Host.Host),
                IsAllowedUrl(UriHelper.GetDisplayUrl(request)),
                NotContainsBlockedKeyWords(UriHelper.GetDisplayUrl(request)),
                NotContainsBlockedExtension(UriHelper.GetDisplayUrl(request))
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