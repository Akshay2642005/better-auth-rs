import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("reset password rejects excess length without consuming its token", async (ctx) => {
  const actor = ctx.actor();
  const missingToken = await actor.client.resetPassword({ token: "", newPassword: "short" });
  expect(missingToken.error?.code).toBe("INVALID_TOKEN");
  const email = ctx.uniqueEmail("reset-length");
  const token = ctx.uniqueToken("reset-length");
  const signup = await actor.client.signUp.email({ email, password: "Password123!", name: "Reset" });
  expect(signup.error).toBeNull();
  await ctx.seedResetPasswordToken({ email, token, expiresAt: "2099-01-01T00:00:00Z" });
  const rejected = await actor.client.resetPassword({ token, newPassword: "a".repeat(129) });
  expect(rejected.error?.code).toBe("PASSWORD_TOO_LONG");
  const accepted = await actor.client.resetPassword({ token, newPassword: "NewPassword123!" });
  expect(accepted.error).toBeNull();
  expect(accepted.data?.status).toBe(true);
  return { rejected: ctx.snapshot(rejected), accepted: ctx.snapshot(accepted) };
});

compatScenario("concurrent password resets consume a token once", async (ctx) => {
  const email = ctx.uniqueEmail("reset-race");
  const token = ctx.uniqueToken("reset-race");
  const signup = await ctx.actor().client.signUp.email({ email, password: "Password123!", name: "Reset race" });
  expect(signup.error).toBeNull();
  await ctx.seedResetPasswordToken({ email, token, expiresAt: "2099-01-01T00:00:00Z" });
  // Concurrent response order is nondeterministic. Compare outcomes after every request settles.
  const responses = await Promise.all(Array.from({ length: 8 }, async () => {
    const response = await fetch(`${ctx.baseURL}/api/auth/reset-password`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ctx.baseURL },
      body: JSON.stringify({ token, newPassword: "NewPassword123!" }),
    });
    const body = await response.json();
    expect(response.status === 200 ? body.status : body.code).toBe(response.status === 200 ? true : "INVALID_TOKEN");
    return response.status;
  }));
  expect(responses.filter(status => status === 200)).toHaveLength(1);
  expect(responses.filter(status => status === 400)).toHaveLength(7);
  const signin = await ctx.actor("fresh").client.signIn.email({ email, password: "NewPassword123!" });
  expect(signin.error).toBeNull();
  return { statuses: responses.sort(), signin: ctx.snapshot(signin) };
});
