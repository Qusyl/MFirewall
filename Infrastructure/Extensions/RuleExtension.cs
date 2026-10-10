
using MFirewallApp.Interface;
using MFirewallApp.Rules.PortScanRule;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.Extensions
{
    public static class RuleExtension
    {
        public static IServiceCollection AddRules(this IServiceCollection services)
        {
            var rules = typeof(PortScanRule).Assembly.GetTypes().Where(t => !t.IsAbstract && !t.IsInterface && typeof(IPacketRule).IsAssignableFrom(t));

            foreach (var rule in rules)
            {
                services.AddSingleton(typeof(IPacketRule), rule);
            }

            return services;
        }
    }
}