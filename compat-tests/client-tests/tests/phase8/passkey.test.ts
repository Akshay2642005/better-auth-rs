import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { compatScenario } from "../../support/scenario";
import { expect } from "bun:test";
import { authenticator, type AuthenticationOptions, type RegistrationOptions } from "./authenticator";

function redactChallenge<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const copy = structuredClone(value as object) as Record<string, unknown>;
  if (
    copy.data &&
    typeof copy.data === "object" &&
    !Array.isArray(copy.data) &&
    "challenge" in (copy.data as Record<string, unknown>)
  ) {
    (copy.data as Record<string, unknown>).challenge = "<challenge>";
  }
  return copy as T;
}

function passkeyActor(ctx: Parameters<Parameters<typeof compatScenario>[1]>[0], name = "primary") {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [passkeyClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

compatScenario("passkey client surface matches TS for options and management errors", async (ctx) => {
  const actor = ctx.actor("primary");
  const passkey = passkeyActor(ctx, "primary");
  const email = ctx.uniqueEmail("phase8-passkey");

  const signup = await actor.client.signUp.email({
    email,
    password: "password123",
    name: "Phase 8 Passkey",
  });

  const registerOptions = await passkey.$fetch("/passkey/generate-register-options", {
    method: "GET",
    query: {
      name: "Laptop Passkey",
      authenticatorAttachment: "cross-platform",
    },
    throw: false,
  });

  const authenticateOptions = await passkey.$fetch("/passkey/generate-authenticate-options", {
    method: "GET",
    throw: false,
  });

  const listPasskeys = await passkey.$fetch("/passkey/list-user-passkeys", {
    method: "GET",
    throw: false,
  });

  const deleteMissing = await passkey.$fetch("/passkey/delete-passkey", {
    method: "POST",
    body: {
      id: "missing-passkey-id",
    },
    throw: false,
  });

  const updateMissing = await passkey.$fetch("/passkey/update-passkey", {
    method: "POST",
    body: {
      id: "missing-passkey-id",
      name: "Renamed Passkey",
    },
    throw: false,
  });

  return {
    signup: ctx.snapshot(signup),
    registerOptions: redactChallenge(ctx.snapshot(registerOptions)),
    authenticateOptions: redactChallenge(ctx.snapshot(authenticateOptions)),
    listPasskeys: ctx.snapshot(listPasskeys),
    deleteMissing: ctx.snapshot(deleteMissing),
    updateMissing: ctx.snapshot(updateMissing),
  };
});

for (const registeredUV of [false, true]) {
  compatScenario(`passkey verifies signed ceremonies with registration UV=${registeredUV}`, async (ctx) => {
    const actor = ctx.actor();
    const signup = await actor.client.signUp.email({
      email: ctx.uniqueEmail("passkey-ceremony"), password: "password123", name: "Passkey Ceremony",
    });
    expect(signup.error).toBeNull();
    const key = authenticator(ctx.uniqueToken("credential"));
    const options = await ctx.rawRequest({ path: "/api/auth/passkey/generate-register-options" });
    expect(options.status).toBe(200);
    const registrationOptions = options.body as RegistrationOptions;
    expect(registrationOptions.authenticatorSelection.userVerification).toBe("preferred");
    const registered = await ctx.rawRequest({
      path: "/api/auth/passkey/verify-registration", method: "POST",
      json: { response: key.register(registrationOptions, ctx.baseURL, registeredUV), name: "Software Authenticator" },
    });
    expect(registered.status).toBe(200);
    const passkey = registered.body as { credentialID: string; userId: string };
    expect(passkey.credentialID).toBe(key.id);
    expect(passkey.userId).toBe(signup.data!.user.id);

    const outcomes = [];
    for (const [index, flags] of [0x01, 0x05].entries()) {
      const loginActor = index === 0 ? "anonymous" : "primary";
      const challenge = await ctx.rawRequest({ actor: loginActor, path: "/api/auth/passkey/generate-authenticate-options" });
      expect(challenge.status).toBe(200);
      const authenticationOptions = challenge.body as AuthenticationOptions;
      if (index === 1) expect(authenticationOptions.allowCredentials![0]!.id).toBe(key.id);
      const assertion = key.authenticate(authenticationOptions, ctx.baseURL, index + 1, flags, registrationOptions.user.id);
      const login = await ctx.rawRequest({ actor: loginActor, path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: assertion } });
      expect(login.status).toBe(200);
      const loggedIn = login.body as { session: { userId: string }; user: { id: string } };
      expect(loggedIn.session.userId).toBe(signup.data!.user.id);
      expect(loggedIn.user.id).toBe(signup.data!.user.id);
      const session = await ctx.actor(loginActor).client.getSession();
      expect(session.data!.user.id).toBe(signup.data!.user.id);
      const replay = await ctx.rawRequest({ actor: loginActor, path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: assertion } });
      expect(replay.status).toBe(400);
      outcomes.push({ login: ctx.snapshot(login), replay: ctx.snapshot(replay) });
    }
    for (const failure of ["presence", "signature", "challenge", "origin", "origin-port", "rpId", "counter"]) {
      const challenge = await ctx.rawRequest({ actor: "invalid", path: "/api/auth/passkey/generate-authenticate-options" });
      const authenticationOptions = challenge.body as AuthenticationOptions;
      const origin = new URL(ctx.baseURL);
      if (failure === "origin-port") origin.port = String(Number(origin.port) + 1);
      const assertion = key.authenticate(
        failure === "challenge" ? { ...authenticationOptions, challenge: "wrong-challenge" }
          : failure === "rpId" ? { ...authenticationOptions, rpId: "attacker.example" } : authenticationOptions,
        failure === "origin" ? "https://attacker.example" : origin.origin,
        failure === "counter" ? 2 : 3,
        failure === "presence" ? 0x04 : 0x01,
        registrationOptions.user.id,
      );
      if (failure === "signature") assertion.response.signature = Buffer.alloc(64).toString("base64url");
      const rejected = await ctx.rawRequest({ actor: "invalid", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: assertion } });
      expect(rejected.status).toBe(400);
      const retry = await ctx.rawRequest({
        actor: "invalid", path: "/api/auth/passkey/verify-authentication", method: "POST",
        json: { response: key.authenticate(authenticationOptions, ctx.baseURL, 3, 0x01, registrationOptions.user.id) },
      });
      expect(retry.status).toBe(400);
      expect((retry.body as { code: string }).code).toBe("CHALLENGE_NOT_FOUND");
      outcomes.push({ failure, rejected: ctx.snapshot(rejected), retry: ctx.snapshot(retry) });
    }
    const pending: { actor: string; options: AuthenticationOptions }[] = [];
    for (const actor of ["earlier-challenge", "later-challenge"]) {
      const login = await ctx.actor(actor).client.signIn.email({
        email: ctx.uniqueEmail("passkey-ceremony"), password: "password123",
      });
      expect(login.error).toBeNull();
      const challenge = await ctx.rawRequest({ actor, path: "/api/auth/passkey/generate-authenticate-options" });
      expect(challenge.status).toBe(200);
      const options = challenge.body as AuthenticationOptions;
      expect(options.allowCredentials![0]!.id).toBe(key.id);
      pending.push({ actor, options });
    }
    const reordered = [];
    for (const [challenge, counter, status] of [[pending[1]!, 4, 200], [pending[0]!, 3, 400]] as const) {
      const response = await ctx.rawRequest({
        actor: challenge.actor, path: "/api/auth/passkey/verify-authentication", method: "POST",
        json: { response: key.authenticate(challenge.options, ctx.baseURL, counter, 0x01, registrationOptions.user.id) },
      });
      expect(response.status).toBe(status);
      reordered.push(ctx.snapshot(response));
    }
    const listed = await ctx.rawRequest({ path: "/api/auth/passkey/list-user-passkeys" });
    expect((listed.body as { counter: number }[])[0]!.counter).toBe(4);
    return { registered: ctx.snapshot(registered), listed: ctx.snapshot(listed), outcomes, reordered };
  });
}
