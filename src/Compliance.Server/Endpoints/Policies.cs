using Compliance.Core;

namespace Compliance.Server;

static partial class Endpoints
{
    static void MapPolicies(IEndpointRouteBuilder routes, ComplianceService s)
    {
        var group = routes.MapGroup("/api/policies");

        group.MapGet(
            "/current",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(tx => s.CurrentRelease(tx));
            }
        );

        // The rule set shipped with this server version, so an upgraded server can adopt new built-in rules
        // through the normal draft, review and publish flow instead of re-seeding its data.
        group.MapGet(
            "/template",
            (HttpContext c) =>
            {
                Require(c, "Reader");
                return PolicySeed.Create();
            }
        );

        group.MapGet(
            "/drafts",
            async (HttpContext c) =>
            {
                Require(c, "Reader");
                return await s.Tx(async tx => (await tx.Drafts()).ToArray());
            }
        );

        group.MapPost(
            "/drafts",
            async (HttpContext c) =>
            {
                var u = Require(c, "Publisher");
                var r = await Body<DraftRequest>(c);
                var doc = r.Document ?? throw new ApiError(400, "Policy required");
                if (
                    doc.SchemaVersion != 1
                    || doc.Mode is not ("Audit" or "Enforce")
                    || doc.RequiredModules == null
                    || doc.RequiredControls == null
                    || doc.TargetDeviceIds == null
                    || doc.Products == null
                    || doc.ApplicationRules == null
                    || doc.BlockDomains == null
                    || !doc.DenyInstalled
                    || !doc.DenyProxy
                    || doc.RequiredModules.Length == 0
                    || doc.Products.Length > 5000
                    || doc.BlockDomains.Length > 1000
                    || doc.ApplicationRules.Length > 1000
                )
                    throw new ApiError(400, "Invalid or incomplete policy");
                try
                {
                    PolicyCrypto.Validate(doc);
                }
                catch (ArgumentException)
                {
                    throw new ApiError(400, "Invalid policy content");
                }
                return await s.Tx(async tx =>
                {
                    var draft = new DraftRecord(
                        Guid.NewGuid().ToString(),
                        doc,
                        u.Username,
                        null,
                        false,
                        r.ImpactReviewed
                    );
                    await tx.InsertDraft(draft, s.Now);
                    await tx.Audit(u.Username, "CreatePolicyDraft", draft.Id, s.Now);
                    return draft;
                });
            }
        );

        group.MapPost(
            "/{id}/approve",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Reviewer");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var d = await tx.GetDraft(id) ?? throw new ApiError(404, "Draft not found");
                    if (d.Published || d.CreatedBy == u.Username || !d.ImpactReviewed)
                        throw new ApiError(409, "Independent reviewer and impact review required");
                    d = d with { ApprovedBy = u.Username };
                    await tx.UpdateDraftReview(id, d.ApprovedBy, d.Published);
                    await tx.Audit(u.Username, "ApprovePolicy", id, s.Now);
                    return d;
                });
            }
        );

        group.MapPost(
            "/{id}/publish",
            async (HttpContext c, string id) =>
            {
                var u = Require(c, "Publisher");
                return await s.Tx(async tx =>
                {
                    await tx.Lock(ComplianceService.PolicyLock);
                    var d = await tx.GetDraft(id) ?? throw new ApiError(404, "Draft not found");
                    if (d.ApprovedBy == u.Username)
                        throw new ApiError(409, "Publisher must differ from reviewer");
                    await s.ValidatePublish(tx, d);
                    var signed = s.Sign(d.Document);
                    await tx.InsertRelease(d.Document.Version, signed, s.Now);
                    await tx.AssignPolicy(d.Document.Version, d.Document.TargetDeviceIds);
                    await tx.UpdateDraftReview(id, d.ApprovedBy, published: true);
                    await tx.Audit(u.Username, "PublishPolicy", id, s.Now);
                    return signed;
                });
            }
        );
    }
}
