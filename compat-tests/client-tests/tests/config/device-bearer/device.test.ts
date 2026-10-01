import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("approved device token authenticates its bound user when Bearer is enabled", async (ctx) => {
  const owner = await ctx.actor("owner").client.signUp.email({ email: ctx.uniqueEmail("device-bearer"), password: "password123", name: "Device Owner" });
  expect(owner.error).toBeNull();
  const issued = await ctx.rawRequest({ path: "/api/auth/device/code", method: "POST", json: { client_id: "bearer-client", scope: "read" } });
  expect(issued.status).toBe(200);
  const code = issued.body as { user_code: string; device_code: string };
  expect((await ctx.rawRequest({ actor: "owner", path: `/api/auth/device?user_code=${code.user_code}` })).status).toBe(200);
  const approved = await ctx.rawRequest({ actor: "owner", path: "/api/auth/device/approve", method: "POST", json: { userCode: code.user_code } });
  expect(approved.status).toBe(200);
  const token = await ctx.rawRequest({ path: "/api/auth/device/token", method: "POST", json: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: code.device_code, client_id: "bearer-client" } });
  expect(token.status).toBe(200);
  const body = token.body as { access_token: string; token_type: string; scope: string };
  expect(body.token_type).toBe("Bearer");
  expect(body.scope).toBe("read");
  const session = await ctx.rawRequest({ actor: "device-client", path: "/api/auth/get-session", headers: { authorization: `Bearer ${body.access_token}` } });
  expect(session.status).toBe(200);
  const authenticated = session.body as { user: { id: string }; session: { userId: string } };
  expect(authenticated.user.id).toBe(owner.data!.user.id);
  expect(authenticated.session.userId).toBe(owner.data!.user.id);
  return { approved: ctx.snapshot(approved), tokenType: body.token_type, scope: body.scope, sessionStatus: session.status, ownerMatched: authenticated.user.id === owner.data!.user.id };
});
