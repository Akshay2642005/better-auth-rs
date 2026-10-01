import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario("organization invitation delivery failures preserve new and resent invitations", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "failed-delivery-owner", "Owner");
  const organization = await owner.orgClient.organization.create({
    name: "Delivery Failure", slug: ctx.uniqueToken("failed-delivery-org"),
  });
  expect(organization.error).toBeNull();
  const mode = (fail: boolean) => ctx.rawRequest({
    method: "POST", path: "/__test/invitation-sender-mode", json: { fail },
  });
  expect((await mode(true)).status).toBe(200);
  try {
    const email = ctx.uniqueEmail("failed-delivery-invitee");
    const request = { organizationId: organization.data!.id, email, role: "member" as const };
    const created = await owner.orgClient.organization.inviteMember(request);
    expect(created.error).toBeNull();
    const shortened = await ctx.rawRequest({
      method: "POST", path: "/__test/shorten-invitation-expiry", json: { id: created.data!.id },
    });
    expect(shortened.status).toBe(200);
    const resent = await owner.orgClient.organization.inviteMember({ ...request, resend: true });
    expect(resent.error).toBeNull();
    expect(resent.data!.id).toBe(created.data!.id);
    expect(new Date(resent.data!.expiresAt).getTime()).toBeGreaterThan(new Date((shortened.body as { expiresAt: string }).expiresAt).getTime());
    const invitations = await owner.orgClient.organization.listInvitations({ query: { organizationId: organization.data!.id } });
    expect(invitations.data).toHaveLength(1);
    expect(invitations.data![0]!.id).toBe(created.data!.id);
    expect(invitations.data![0]!.expiresAt).toEqual(resent.data!.expiresAt);
    const emails = await ctx.rawRequest({ path: `/__test/invitation-emails?email=${encodeURIComponent(email)}` });
    expect(emails.body).toEqual([]);
    expect((await mode(false)).status).toBe(200);
    const delivered = await owner.orgClient.organization.inviteMember({ ...request, resend: true });
    expect(delivered.error).toBeNull();
    expect(delivered.data!.id).toBe(created.data!.id);
    const finalEmails = await ctx.rawRequest({ path: `/__test/invitation-emails?email=${encodeURIComponent(email)}` });
    expect(finalEmails.body).toEqual([{ id: created.data!.id, email, role: "member" }]);
    return { created, resent, invitations, emails, delivered, finalEmails };
  } finally {
    await mode(false);
  }
});

compatScenario("organization duplicate invitations require resend and preserve invitation identity", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "resend-owner", "Owner");
  const organization = await owner.orgClient.organization.create({
    name: "Resend Organization", slug: ctx.uniqueToken("resend-org"),
  });
  expect(organization.error).toBeNull();
  const email = ctx.uniqueEmail("resend-invitee");
  const request = { organizationId: organization.data!.id, email, role: "member" as const };
  const first = await owner.orgClient.organization.inviteMember(request);
  expect(first.error).toBeNull();
  const readEmails = () => ctx.rawRequest({ path: `/__test/invitation-emails?email=${encodeURIComponent(email)}` });
  const firstEmails = await readEmails();
  expect(firstEmails.body).toHaveLength(1);
  const duplicate = await owner.orgClient.organization.inviteMember(request);
  expect(duplicate.error?.status).toBe(400);
  expect(duplicate.error?.code).toBe("USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION");
  const duplicateEmails = await readEmails();
  expect(duplicateEmails.body).toHaveLength(1);
  const shortened = await ctx.rawRequest({
    method: "POST",
    path: "/__test/shorten-invitation-expiry",
    json: { id: first.data!.id },
  });
  expect(shortened.status).toBe(200);
  const resent = await owner.orgClient.organization.inviteMember({ ...request, role: "admin", resend: true });
  expect(resent.error).toBeNull();
  expect(resent.data!.id).toBe(first.data!.id);
  expect(resent.data!.role).toBe("member");
  expect(resent.data!.inviterId).toBe(first.data!.inviterId);
  expect(new Date(resent.data!.expiresAt).getTime()).toBeGreaterThan(
    new Date((shortened.body as { expiresAt: string }).expiresAt).getTime(),
  );
  const resentEmails = await readEmails();
  expect(resentEmails.body).toHaveLength(2);
  expect(resentEmails.body).toEqual([
    { id: first.data!.id, email, role: "member" },
    { id: first.data!.id, email, role: "member" },
  ]);
  const invitations = await owner.orgClient.organization.listInvitations({ query: { organizationId: organization.data!.id } });
  expect(invitations.data).toHaveLength(1);
  expect(invitations.data![0]!.expiresAt).toEqual(resent.data!.expiresAt);
  return { first, duplicate, shortened, resent, firstEmails, duplicateEmails, resentEmails, invitations };
});

compatScenario("organization invitation happy path covers list and accept flows", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-invite-owner", "Owner");
  const invitee = await signUpUser(ctx, "invitee", "phase6-invite-invitee", "Invitee");
  const slug = ctx.uniqueToken("phase6-invite-org");

  const organization = await owner.orgClient.organization.create({
    name: "Invite Org",
    slug,
  });
  const invitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: invitee.email,
    role: "member",
  });
  const getInvitation = await invitee.orgClient.organization.getInvitation({
    query: {
      id: invitation.data?.id ?? "",
    },
  });
  const listInvitations = await owner.orgClient.organization.listInvitations({
    query: {
      organizationId: organization.data?.id,
    },
  });
  const listUserInvitations = await invitee.orgClient.organization.listUserInvitations();
  const acceptInvitation = await invitee.orgClient.organization.acceptInvitation({
    invitationId: invitation.data?.id ?? "",
  });
  const fullOrganizationAfterAccept =
    await invitee.orgClient.organization.getFullOrganization();

  return {
    organization: ctx.snapshot(organization),
    invitation: ctx.snapshot(invitation),
    getInvitation: ctx.snapshot(getInvitation),
    listInvitations: ctx.snapshot(listInvitations),
    listUserInvitations: ctx.snapshot(listUserInvitations),
    acceptInvitation: ctx.snapshot(acceptInvitation),
    fullOrganizationAfterAccept: ctx.snapshot(fullOrganizationAfterAccept),
  };
});

compatScenario("organization invitation validation, reject, and cancel flows match TS", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-validate-owner", "Owner");
  const admin = await signUpUser(ctx, "admin", "phase6-validate-admin", "Admin");
  const rejectUser = await signUpUser(ctx, "reject-user", "phase6-reject-user", "Reject User");
  const cancelUser = await signUpUser(ctx, "cancel-user", "phase6-cancel-user", "Cancel User");
  const slug = ctx.uniqueToken("phase6-validate-org");

  const organization = await owner.orgClient.organization.create({
    name: "Validation Org",
    slug,
  });

  const adminInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: admin.email,
    role: "admin",
  });
  const acceptedAdmin = await admin.orgClient.organization.acceptInvitation({
    invitationId: adminInvitation.data?.id ?? "",
  });
  const adminInvitingOwner = await admin.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: ctx.uniqueEmail("phase6-owner-role"),
    role: "owner",
  });
  const invalidRoleInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: ctx.uniqueEmail("phase6-invalid-role"),
    role: "super-invalid-role-123" as never,
  });

  const rejectInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: rejectUser.email,
    role: "member",
  });
  const rejected = await rejectUser.orgClient.organization.rejectInvitation({
    invitationId: rejectInvitation.data?.id ?? "",
  });

  const cancelInvitation = await owner.orgClient.organization.inviteMember({
    organizationId: organization.data?.id ?? "",
    email: cancelUser.email,
    role: "member",
  });
  const canceled = await owner.orgClient.organization.cancelInvitation({
    invitationId: cancelInvitation.data?.id ?? "",
  });

  return {
    organization: ctx.snapshot(organization),
    adminInvitation: ctx.snapshot(adminInvitation),
    acceptedAdmin: ctx.snapshot(acceptedAdmin),
    adminInvitingOwner: ctx.snapshot(adminInvitingOwner),
    invalidRoleInvitation: ctx.snapshot(invalidRoleInvitation),
    rejectInvitation: ctx.snapshot(rejectInvitation),
    rejected: ctx.snapshot(rejected),
    cancelInvitation: ctx.snapshot(cancelInvitation),
    canceled: ctx.snapshot(canceled),
  };
});
