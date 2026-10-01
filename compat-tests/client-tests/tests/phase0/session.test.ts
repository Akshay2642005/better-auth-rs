import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("get session after sign-in returns session and user", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase0-session");
  await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Session User",
  });

  const session = await primary.client.getSession();
  expect(session.error).toBeNull();
  const raw = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(raw.status).toBe(200);
  const wire = raw.body as {
    user: { createdAt: string; updatedAt: string };
    session: { createdAt: string; updatedAt: string; expiresAt: string };
  };
  for (const [sdkDate, wireDate] of [
    [session.data!.user.createdAt, wire.user.createdAt],
    [session.data!.user.updatedAt, wire.user.updatedAt],
    [session.data!.session.createdAt, wire.session.createdAt],
    [session.data!.session.updatedAt, wire.session.updatedAt],
    [session.data!.session.expiresAt, wire.session.expiresAt],
  ] as const) {
    expect(sdkDate).toBeInstanceOf(Date);
    expect(wireDate).toMatch(/\.\d{3}Z$/);
    expect(sdkDate.toISOString()).toBe(wireDate);
  }

  return {
    session: ctx.snapshot(session),
  };
});

compatScenario("get session without auth returns null", async (ctx) => {
  const primary = ctx.actor();
  const session = await primary.client.getSession();

  return {
    session: ctx.snapshot(session),
  };
});
