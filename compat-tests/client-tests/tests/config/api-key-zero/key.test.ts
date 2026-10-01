import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("zero key length uses the upstream default and rejects the public prefix", async (ctx) => {
  const signup = await ctx.actor().client.signUp.email({
    email: ctx.uniqueEmail("zero-key"), password: "password123", name: "Key Owner",
  });
  expect(signup.error).toBeNull();
  const issued = await ctx.rawRequest({
    path: "/api/auth/api-key/create", method: "POST", json: { prefix: "node_" },
  });
  expect(issued.status).toBe(200);
  const key = issued.body as { key: string; referenceId: string };
  expect(key.key).toMatch(/^node_[a-zA-Z]{64}$/);
  expect(key.referenceId).toBe(signup.data!.user.id);
  const verify = async (value: string) => ctx.rawRequest({
    path: "/__test/api-key/verify", method: "POST", json: { key: value },
  });
  const valid = await verify(key.key);
  expect((valid.body as { valid: boolean }).valid).toBe(true);
  const prefix = await verify("node_");
  expect((prefix.body as { valid: boolean }).valid).toBe(false);
  return { keyLength: key.key.length, valid: (valid.body as { valid: boolean }).valid, prefix };
});
