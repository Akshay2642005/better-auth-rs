import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("invalid sign-out bodies preserve the authenticated session", async (ctx) => {
  const actor = ctx.actor();
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("invalid-logout-body"), password: "password123", name: "Logout User",
  });
  expect(signup.error).toBeNull();
  const cases = [
    { body: null, message: "[body] Invalid input: expected object, received null" },
    { body: [], message: "[body] Invalid input: expected object, received array" },
    { body: "text", message: "[body] Invalid input: expected object, received string" },
    { body: { callbackURL: null }, message: "[body.callbackURL] Invalid input: expected string, received null" },
    { body: { disableRedirect: null }, message: "[body.disableRedirect] Invalid input: expected boolean, received null" },
    { body: { state: null }, message: "[body.state] Invalid input: expected string, received null" },
    { body: { disableRedirect: "yes" }, message: "[body.disableRedirect] Invalid input: expected boolean, received string" },
    { body: { state: 42 }, message: "[body.state] Invalid input: expected string, received number" },
    {
      body: { callbackURL: null, disableRedirect: "yes", state: false },
      message: "[body.callbackURL] Invalid input: expected string, received null; [body.disableRedirect] Invalid input: expected boolean, received string; [body.state] Invalid input: expected string, received boolean",
    },
  ];
  const responses = [];
  for (const input of cases) {
    const response = await ctx.rawRequest({ path: "/api/auth/sign-out", method: "POST", json: input.body });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ code: "VALIDATION_ERROR", message: input.message });
    const session = await actor.client.getSession();
    expect(session.data?.user.id).toBe(signup.data!.user.id);
    expect(session.data?.session.token).toBe(signup.data!.token);
    responses.push(response);
  }
  const malformed = await ctx.rawRequest({
    path: "/api/auth/sign-out", method: "POST", headers: { "content-type": "application/json" }, body: "{",
  });
  expect(malformed.status).toBe(400);
  expect(malformed.body).toEqual({ code: "BAD_REQUEST", message: "Invalid JSON in request body" });
  expect((await actor.client.getSession()).data?.session.token).toBe(signup.data!.token);
  const logout = await ctx.rawRequest({ path: "/api/auth/sign-out", method: "POST" });
  expect(logout.status).toBe(200);
  expect(logout.body).toEqual({ success: true });
  expect((await actor.client.getSession()).data).toBeNull();
  return { responses, malformed, logout };
});

compatScenario("provider logout returns end-session parameters and ends the local session", async (ctx) => {
  const actor = ctx.actor();
  const email = ctx.uniqueEmail("provider-logout");
  await actor.client.signUp.email({ email, password: "password123", name: "Logout User" });
  await ctx.seedOAuthAccount({ email, providerId: "mock", idToken: "logout-id-token" });
  const logout = await ctx.rawRequest({
    path: "/api/auth/sign-out", method: "POST", redirect: "manual",
    json: { callbackURL: "/after-logout", state: "logout-state" },
  });
  expect(logout.status).toBe(200);
  const body = logout.body as { success: boolean; redirect: boolean; url: string };
  expect(body.success).toBe(true);
  expect(body.redirect).toBe(true);
  expect(logout.location).toBe(body.url);
  const url = new URL(body.url);
  expect(url.origin).toBe("https://idp.example.test");
  expect(url.pathname).toBe("/logout");
  expect(url.searchParams.get("id_token_hint")).toBe("logout-id-token");
  expect(url.searchParams.get("client_id")).toBe("mock-client-id");
  expect(url.searchParams.get("state")).toBe("logout-state");
  const callback = url.searchParams.get("post_logout_redirect_uri")!;
  expect(new URL(callback).pathname).toBe("/after-logout");
  expect(new URL(callback).origin).toBe(new URL(ctx.baseURL).origin);
  const session = await actor.client.getSession();
  expect(session.data).toBeNull();
  return { status: logout.status, success: body.success, redirect: body.redirect, session };
});

compatScenario("provider logout disableRedirect omits Location and only includes state with a callback", async (ctx) => {
  const actor = ctx.actor();
  const email = ctx.uniqueEmail("provider-logout-no-redirect");
  await actor.client.signUp.email({ email, password: "password123", name: "Logout User" });
  await ctx.seedOAuthAccount({ email, providerId: "mock", idToken: "logout-id-token" });
  const logout = await ctx.rawRequest({
    path: "/api/auth/sign-out", method: "POST", redirect: "manual",
    json: { disableRedirect: true, state: "unused-state" },
  });
  expect(logout.status).toBe(200);
  expect(logout.location).toBeNull();
  const body = logout.body as { success: boolean; redirect: boolean; url: string };
  expect(body).toEqual({ success: true, redirect: false, url: "https://idp.example.test/logout?id_token_hint=logout-id-token" });
  const session = await actor.client.getSession();
  expect(session.data).toBeNull();
  await actor.client.signIn.email({ email, password: "password123" });
  await ctx.seedOAuthAccount({ email, providerId: "mock", idToken: null });
  const withoutIdToken = await ctx.rawRequest({
    path: "/api/auth/sign-out", method: "POST", redirect: "manual",
    json: { disableRedirect: true, state: "unused-state" },
  });
  expect(withoutIdToken.body).toEqual({ success: true, redirect: false, url: "https://idp.example.test/logout?client_id=mock-client-id" });
  return { logout, session, withoutIdToken };
});
