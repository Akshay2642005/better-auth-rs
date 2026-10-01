import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("device issuance retries collisions and stops after three attempts", async (ctx) => {
  const issue = () => ctx.rawRequest({ path: "/api/auth/device/code", method: "POST", json: { client_id: "collision-client" } });
  const first = await issue();
  expect(first.status).toBe(200);
  expect((first.body as Record<string, unknown>).user_code).toBe("same-code");
  const second = await issue();
  expect(second.status).toBe(200);
  expect((second.body as Record<string, unknown>).user_code).toBe("next-code");
  const exhausted = await issue();
  expect(exhausted.status).toBe(500);
  expect(exhausted.body).toEqual({ error: "server_error", error_description: "Failed to generate a unique device code" });
  const next = await issue();
  expect(next.status).toBe(200);
  expect((next.body as Record<string, unknown>).user_code).toBe("after-code");
  return { firstStatus: first.status, secondStatus: second.status, exhausted: ctx.snapshot(exhausted), nextStatus: next.status };
});
