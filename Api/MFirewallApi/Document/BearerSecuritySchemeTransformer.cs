using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace MFirewallApi.Document
{
    internal sealed class BearerSecuritySchemeTransformer(IAuthenticationSchemeProvider authProvider) 
        : IOpenApiDocumentTransformer
    {
        public async Task TransformAsync(
            OpenApiDocument document, 
            OpenApiDocumentTransformerContext context, 
            CancellationToken cancellationToken)
        {
            var schemes = await authProvider.GetAllSchemesAsync();
            if (!schemes.Any(sch => sch.Name == "Bearer"))
                return;

            var bearerScheme = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Вставьте JWT токен сюда"
            };

       
            document.Components ??= new OpenApiComponents();
            document.AddComponent("Bearer", bearerScheme);

           
            var requirement = new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference("Bearer", document)] = []
            };

            if (document.Paths is not null)
            {
                foreach (var operation in document.Paths.Values
                    .SelectMany(p => p.Operations?.Select(op => op.Value) ?? []))
                {
                    operation.Security ??= new List<OpenApiSecurityRequirement>();
                    operation.Security.Add(requirement);
                }
            }
        }
    }
}