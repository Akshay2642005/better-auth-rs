import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("custom device user codes preserve exact punctuation", async (ctx) => {
  const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("custom-device"), password: "password123", name: "Device User" });
  expect(signup.error).toBeNull();
  const code = await ctx.rawRequest({ path: "/api/auth/device/code", method: "POST", json: { client_id: "custom-client" } });
  expect(code.status).toBe(200);
  const changedCase = await ctx.rawRequest({ path: "/api/auth/device?user_code=CUSTOM-CODE" });
  expect(changedCase.status).toBe(400);
  const verify = await ctx.rawRequest({ actor: "primary", path: "/api/auth/device?user_code=custom-code" });
  expect(verify.status).toBe(200);
  const approve = await ctx.rawRequest({ actor: "primary", path: "/api/auth/device/approve", method: "POST", json: { userCode: "custom-code" } });
  expect(approve.status).toBe(200);
  return { verify: ctx.snapshot(verify), approve: ctx.snapshot(approve) };
});
