import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("redirect targets reject truthy JSON values that are not strings", async (ctx) => {
  const results = [];
  for (const [field, label] of [
    ["callbackURL", "callbackURL"],
    ["redirectTo", "redirectURL"],
    ["errorCallbackURL", "errorCallbackURL"],
    ["newUserCallbackURL", "newUserCallbackURL"],
  ]) {
    for (const value of [true, 1, [], {}]) {
      const response = await ctx.rawRequest({
        path: "/api/auth/sign-out",
        method: "POST",
        json: { [field]: value },
      });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({ message: `Invalid ${label}: expected a string` });
      results.push(response);
    }
  }
  return results;
});

compatScenario("redirect target selection gives callback body precedence and ignores other query targets", async (ctx) => {
  const results = [];
  for (const field of ["callbackURL", "redirectTo", "errorCallbackURL", "newUserCallbackURL"]) {
    const query = new URLSearchParams({ [field]: "https://untrusted.example/callback" });
    const response = await ctx.rawRequest({
      path: `/api/auth/sign-out?${query}`,
      method: "POST",
      json: field === "callbackURL" ? { callbackURL: "/signed-out" } : {},
    });
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ success: true });
    results.push(response);
  }
  return results;
});

compatScenario("falsy callback body values fall back to the query target", async (ctx) => {
  const results = [];
  for (const callbackURL of [null, false, 0, ""]) {
    const response = await ctx.rawRequest({
      path: "/api/auth/sign-out?callbackURL=https%3A%2F%2Funtrusted.example%2Fcallback",
      method: "POST",
      json: { callbackURL },
    });
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ code: "INVALID_CALLBACK_URL", message: "Invalid callbackURL" });
    results.push(response);
  }
  return results;
});

compatScenario("first login rejects untrusted Origin and Referer without cookies or Fetch Metadata", async (ctx) => {
  const results = [];
  for (const path of ["/sign-up/email", "/sign-in/email"]) {
    for (const headers of [
      { origin: "https://untrusted.example" },
      { origin: "", referer: "https://untrusted.example/login" },
    ]) {
      const response = await ctx.rawRequest({
        path: `/api/auth${path}`,
        method: "POST",
        headers,
        json: { email: ctx.uniqueEmail("origin"), password: "Password123!", name: "Origin" },
      });
      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({ code: "INVALID_ORIGIN" });
      results.push(response);
    }
  }
  return results;
});

compatScenario("password length uses UTF-16 code units", async (ctx) => {
  const results = [];
  for (const [index, [password, status]] of [
    ["密码密码", 400],
    ["😀".repeat(4), 200],
    ["密".repeat(128), 200],
    ["密".repeat(129), 400],
  ].entries()) {
    const response = await ctx.rawRequest({
      actor: `length-${index}`,
      path: "/api/auth/sign-up/email",
      method: "POST",
      json: { email: ctx.uniqueEmail(`length-${index}`), password, name: "Length" },
    });
    expect(response.status).toBe(status);
    results.push({ status: response.status });
  }
  return results;
});

compatScenario("default password hashing normalizes Unicode with NFKC", async (ctx) => {
  const email = ctx.uniqueEmail("nfkc");
  const signup = await ctx.actor().client.signUp.email({ email, password: "Password１２３!", name: "NFKC" });
  expect(signup.error).toBeNull();
  const signin = await ctx.actor("fresh").client.signIn.email({ email, password: "Password123!" });
  expect(signin.error).toBeNull();
  expect(signin.data?.user.email).toBe(email);
  return { signup: ctx.snapshot(signup), signin: ctx.snapshot(signin) };
});

compatScenario("get session explicitly prevents HTTP caching", async (ctx) => {
  const response = await ctx.actor().fetch("/api/auth/get-session");
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("pragma")).toBe("no-cache");
  return { cacheControl: response.headers.get("cache-control"), pragma: response.headers.get("pragma") };
});
