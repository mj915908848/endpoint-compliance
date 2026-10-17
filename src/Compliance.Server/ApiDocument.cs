using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Compliance.Server;

/// <summary>
/// The OpenAPI document of the management API, served to signed-in administrators at /api/openapi.json. The UI's
/// types are generated from a copy kept in ui/openapi.json, which a test keeps equal to what the server describes.
/// </summary>
public static class ApiDocument
{
    public const string Path = "/api/openapi.json";

    public static void Configure(OpenApiOptions o)
    {
        o.AddSchemaTransformer(
            (schema, _, _) =>
            {
                // Numbers are also read from strings, which the generator lists as a second type; nothing here sends
                // them so, and generated types are clearer without it.
                if (
                    schema.Type is { } type
                    && (type & (JsonSchemaType.Integer | JsonSchemaType.Number)) != 0
                    && (type & JsonSchemaType.String) != 0
                )
                {
                    schema.Type = type & ~JsonSchemaType.String;
                    schema.Pattern = null;
                }
                return Task.CompletedTask;
            }
        );
        o.AddDocumentTransformer(
            (document, _, _) =>
            {
                // The same document whatever the server's release or address, so the copy in ui/ only changes with
                // the API.
                document.Info = new() { Title = "Endpoint compliance management API", Version = "v1" };
                document.Servers = [];
                MarkResponsesRequired(document);
                return Task.CompletedTask;
            }
        );
    }

    /// <summary>
    /// Responses always carry every property, defaults included, so properties of everything a response can contain
    /// are required. Schemas only requests use keep their optional properties.
    /// </summary>
    static void MarkResponsesRequired(OpenApiDocument document)
    {
        var components = document.Components?.Schemas ?? new Dictionary<string, IOpenApiSchema>();
        var seen = new HashSet<string>();
        void Visit(IOpenApiSchema? schema)
        {
            switch (schema)
            {
                case OpenApiSchemaReference reference:
                    if (reference.Reference.Id is { } id && seen.Add(id) && components.TryGetValue(id, out var target))
                        Visit(target);
                    break;
                case OpenApiSchema s:
                    if (s.Properties is { Count: > 0 } properties)
                    {
                        s.Required ??= new HashSet<string>();
                        foreach (var (name, property) in properties)
                        {
                            s.Required.Add(name);
                            Visit(property);
                        }
                    }
                    Visit(s.Items);
                    Visit(s.AdditionalProperties);
                    foreach (var part in (s.AllOf ?? []).Concat(s.AnyOf ?? []).Concat(s.OneOf ?? []))
                        Visit(part);
                    break;
            }
        }
        foreach (var path in document.Paths.Values)
        foreach (var operation in path.Operations?.Values.AsEnumerable() ?? [])
        foreach (var response in operation.Responses?.Values.AsEnumerable() ?? [])
        foreach (var content in response.Content?.Values.AsEnumerable() ?? [])
            Visit(content.Schema);
    }
}
