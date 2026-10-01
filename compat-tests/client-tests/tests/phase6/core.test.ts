import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario("organization metadata lookup enforces membership and clears invalid active state", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "metadata-owner", "Owner");
  const outsider = await signUpUser(ctx, "outsider", "metadata-outsider", "Outsider");
  const query = (actor: string, suffix = "") => ctx.rawRequest({ actor, path: `/api/auth/organization/get-organization${suffix}` });
  const noActive = await query("owner");
  expect(noActive.status).toBe(200);
  expect(noActive.body).toBeNull();
  const organization = await owner.orgClient.organization.create({ name: "Metadata Organization", slug: ctx.uniqueToken("metadata-org") });
  expect(organization.error).toBeNull();
  const active = await query("owner");
  expect(active.status).toBe(200);
  expect((active.body as { id: string }).id).toBe(organization.data!.id);
  expect(active.body).not.toHaveProperty("members");
  expect(active.body).not.toHaveProperty("invitations");
  const slug = await query("owner", `?organizationId=missing&organizationSlug=${organization.data!.slug}`);
  expect(slug.body).toEqual(active.body);
  const missing = await query("owner", "?organizationId=missing");
  expect(missing.status).toBe(400);
  expect((missing.body as { code: string }).code).toBe("ORGANIZATION_NOT_FOUND");
  await outsider.orgClient.organization.create({ name: "Other Organization", slug: ctx.uniqueToken("other-org") });
  const forbidden = await query("outsider", `?organizationId=${organization.data!.id}`);
  expect(forbidden.status).toBe(403);
  expect((forbidden.body as { code: string }).code).toBe("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
  const afterForbidden = await query("outsider");
  expect(afterForbidden.body).toBeNull();
  const anonymous = await query("anonymous");
  expect(anonymous.status).toBe(401);
  return { noActive, active, slug, missing, forbidden, afterForbidden, anonymous };
});

compatScenario("organization core lifecycle matches TS", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-core-owner", "Org Owner");
  const firstSlug = ctx.uniqueToken("phase6-first-org");
  const secondSlug = ctx.uniqueToken("phase6-second-org");
  const availableSlug = ctx.uniqueToken("phase6-available-org");

  const checkAvailable = await owner.orgClient.organization.checkSlug({
    slug: availableSlug,
  });

  const firstOrganization = await owner.orgClient.organization.create({
    name: "Alpha Org",
    slug: firstSlug,
  });
  const secondOrganization = await owner.orgClient.organization.create({
    name: "Beta Org",
    slug: secondSlug,
  });

  const checkTaken = await owner.orgClient.organization.checkSlug({
    slug: firstSlug,
  });

  const listedOrganizations = await owner.orgClient.organization.list();
  const updateFirst = await owner.orgClient.organization.update({
    organizationId: firstOrganization.data?.id ?? "",
    data: {
      name: "Alpha Org Renamed",
      metadata: {
        tier: "gold",
      },
    },
  });
  const activeSecondBySlug = await owner.orgClient.organization.setActive({
    organizationSlug: secondSlug,
  });
  const fullOrganizationBySlugPrecedence =
    await owner.orgClient.organization.getFullOrganization({
      query: {
        organizationId: firstOrganization.data?.id,
        organizationSlug: secondSlug,
      },
    });
  const clearActiveOrganization = await owner.orgClient.organization.setActive({
    organizationId: null,
  });
  const fullOrganizationWithoutActive =
    await owner.orgClient.organization.getFullOrganization();

  return {
    checkAvailable: ctx.snapshot(checkAvailable),
    firstOrganization: ctx.snapshot(firstOrganization),
    secondOrganization: ctx.snapshot(secondOrganization),
    checkTaken: ctx.snapshot(checkTaken),
    listedOrganizations: ctx.snapshot(listedOrganizations),
    updateFirst: ctx.snapshot(updateFirst),
    activeSecondBySlug: ctx.snapshot(activeSecondBySlug),
    fullOrganizationBySlugPrecedence: ctx.snapshot(fullOrganizationBySlugPrecedence),
    clearActiveOrganization: ctx.snapshot(clearActiveOrganization),
    fullOrganizationWithoutActive: ctx.snapshot(fullOrganizationWithoutActive),
  };
});

compatScenario("organization delete returns the deleted org and clears active state", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-delete-owner", "Delete Owner");
  const slug = ctx.uniqueToken("phase6-delete-org");

  const created = await owner.orgClient.organization.create({
    name: "Delete Me",
    slug,
  });
  const deleted = await owner.orgClient.organization.delete({
    organizationId: created.data?.id ?? "",
  });
  const fullOrganizationAfterDelete = await owner.orgClient.organization.getFullOrganization();

  return {
    created: ctx.snapshot(created),
    deleted: ctx.snapshot(deleted),
    fullOrganizationAfterDelete: ctx.snapshot(fullOrganizationAfterDelete),
  };
});

compatScenario("organization create can keep the current active org and full organization honors membersLimit", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-keep-active-owner", "Owner");
  const member = await signUpUser(ctx, "member", "phase6-keep-active-member", "Member");
  const firstSlug = ctx.uniqueToken("phase6-keep-active-first");
  const secondSlug = ctx.uniqueToken("phase6-keep-active-second");

  const firstOrganization = await owner.orgClient.organization.create({
    name: "Keep Active First",
    slug: firstSlug,
  });
  const initialSession = await owner.client.getSession();
  const secondOrganization = await owner.orgClient.organization.create({
    name: "Keep Active Second",
    slug: secondSlug,
    keepCurrentActiveOrganization: true,
  });
  const sessionAfterSecondCreate = await owner.client.getSession();

  const invitation = await owner.orgClient.organization.inviteMember({
    organizationId: firstOrganization.data?.id ?? "",
    email: member.email,
    role: "member",
  });
  const acceptedInvitation = await member.orgClient.organization.acceptInvitation({
    invitationId: invitation.data?.id ?? "",
  });
  const limitedOrganization = await owner.orgClient.organization.getFullOrganization({
    query: {
      organizationId: firstOrganization.data?.id,
      membersLimit: 1,
    },
  });

  return {
    firstOrganization: ctx.snapshot(firstOrganization),
    initialSession: ctx.snapshot(initialSession),
    secondOrganization: ctx.snapshot(secondOrganization),
    sessionAfterSecondCreate: ctx.snapshot(sessionAfterSecondCreate),
    invitation: ctx.snapshot(invitation),
    acceptedInvitation: ctx.snapshot(acceptedInvitation),
    limitedOrganization: ctx.snapshot(limitedOrganization),
  };
});
