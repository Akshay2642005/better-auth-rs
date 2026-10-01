import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

compatScenario("session update and sign-out validate JSON media types before authentication", async (ctx) => {
  const owner = ctx.actor("session-owner");
  const signup = await owner.client.signUp.email({
    email: ctx.uniqueEmail("session-content-type"), password: "password123", name: "Session Owner",
  });
  expect(signup.error).toBeNull();
  const responses = [];
  for (const actor of ["session-owner", "anonymous"]) {
    for (const path of ["/api/auth/update-session", "/api/auth/sign-out"]) {
      for (const contentType of [undefined, "text/plain", "application/x-www-form-urlencoded", "application/problem+json"]) {
        const response = await ctx.rawRequest({
          actor, path, method: "POST",
          headers: contentType ? { "content-type": contentType } : undefined,
          body: new TextEncoder().encode("{}"),
        });
        expect(response.status).toBe(415);
        expect(response.body).toEqual({
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: contentType
            ? `Content-Type "${contentType}" is not allowed. Allowed types: application/json`
            : "Content-Type is required. Allowed types: application/json",
        });
        responses.push({ actor, path, contentType: contentType ?? null, response });
      }
    }
    const accepted = await ctx.rawRequest({
      actor, path: "/api/auth/update-session", method: "POST",
      headers: { "content-type": "APPLICATION/JSON; charset=utf-8" }, body: "{}",
    });
    expect(accepted.status).toBe(actor === "anonymous" ? 401 : 400);
    expect(accepted.body).toEqual(actor === "anonymous"
      ? { code: "UNAUTHORIZED", message: "Unauthorized" }
      : { message: "No fields to update" });
    responses.push({ actor, accepted });
  }
  const session = await owner.client.getSession();
  expect(session.data?.session.token).toBe(signup.data!.token);
  return { responses, session };
});

compatScenario("session update validates the body before requiring a session", async (ctx) => {
  const owner = ctx.actor("session-owner");
  const signup = await owner.client.signUp.email({
    email: ctx.uniqueEmail("session-update-body"),
    password: "password123",
    name: "Session Owner",
  });
  expect(signup.error).toBeNull();
  const cases = [
    { name: "null", body: "null", received: "null" },
    { name: "array", body: "[]", received: "array" },
    { name: "string", body: '"text"', received: "string" },
    { name: "number", body: "1", received: "number" },
    { name: "boolean", body: "false", received: "boolean" },
    { name: "malformed", body: "{" },
    { name: "empty-json", body: "", received: "undefined" },
    { name: "no-body", body: undefined, received: "undefined" },
  ];
  const responses = [];
  for (const actor of ["session-owner", "anonymous"]) {
    for (const input of cases) {
      const response = await ctx.rawRequest({
        actor,
        method: "POST",
        path: "/api/auth/update-session",
        headers: input.name === "no-body" ? undefined : { "content-type": "application/json" },
        body: input.body,
      });
      expect(response.status).toBe(400);
      expect(response.body).toEqual(input.received
        ? { code: "VALIDATION_ERROR", message: `[body] Invalid input: expected record, received ${input.received}` }
        : { code: "BAD_REQUEST", message: "Invalid JSON in request body" });
      responses.push({ actor, name: input.name, response });
    }
    const empty = await ctx.rawRequest({
      actor, method: "POST", path: "/api/auth/update-session", json: {},
    });
    expect(empty.status).toBe(actor === "anonymous" ? 401 : 400);
    expect(empty.body).toEqual(actor === "anonymous"
      ? { code: "UNAUTHORIZED", message: "Unauthorized" }
      : { message: "No fields to update" });
    responses.push({ actor, name: "empty-object", response: empty });
  }
  return responses;
});

compatScenario("session update protects plugin fields and rejects an empty update", async (ctx) => {
  const actor = ctx.actor("session-owner");
  const signup = await actor.client.signUp.email({
    email: ctx.uniqueEmail("session-update"),
    password: "password123",
    name: "Session Owner",
  });
  expect(signup.error).toBeNull();
  const responses = [];
  for (const field of ["activeOrganizationId", "impersonatedBy"]) {
    const denied = await ctx.rawRequest({
      actor: "session-owner",
      method: "POST",
      path: "/api/auth/update-session",
      json: { [field]: "other-user-or-organization" },
    });
    expect(denied.status).toBe(400);
    expect(denied.body).toEqual({
      code: "FIELD_NOT_ALLOWED",
      message: `${field} is not allowed to be set`,
    });
    responses.push(denied);
  }
  for (const body of [
    { activeOrganizationId: null, impersonatedBy: false },
    { activeOrganizationId: "", impersonatedBy: 0 },
    { token: "replacement", userId: "another-user" },
  ]) {
    const empty = await ctx.rawRequest({
      actor: "session-owner",
      method: "POST",
      path: "/api/auth/update-session",
      json: body,
    });
    expect(empty.status).toBe(400);
    expect(empty.body).toEqual({ message: "No fields to update" });
    responses.push(empty);
  }
  const anonymous = await ctx.rawRequest({
    actor: "anonymous",
    method: "POST",
    path: "/api/auth/update-session",
    json: {},
  });
  expect(anonymous.status).toBe(401);
  expect(anonymous.body).toEqual({ code: "UNAUTHORIZED", message: "Unauthorized" });
  const session = await actor.client.getSession();
  expect(session.data?.user.id).toBe(signup.data!.user.id);
  expect(session.data?.session.token).toBe(signup.data!.token);
  return { responses, anonymous, session: ctx.snapshot(session) };
});
