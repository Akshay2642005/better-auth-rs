import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("device verification rejects the sixth guess from one IP", async (ctx) => {
  const statuses = [];
  for (let index = 0; index < 6; index++) {
    const response = await ctx.rawRequest({ path: "/api/auth/device?user_code=UNKNOWN", headers: { "x-forwarded-for": "198.51.100.10" } });
    statuses.push(response.status);
    if (index === 5) expect(response.body).toEqual({ message: "Too many requests. Please try again later." });
  }
  expect(statuses).toEqual([400, 400, 400, 400, 400, 429]);
  const limited = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/device?user_code=UNKNOWN`, { headers: { "x-forwarded-for": "198.51.100.10" } });
  expect(limited.status).toBe(429);
  expect(Number(limited.headers.get("x-retry-after"))).toBeGreaterThan(0);
  expect(Number(limited.headers.get("x-retry-after"))).toBeLessThanOrEqual(1800);
  const otherClient = await ctx.rawRequest({ path: "/api/auth/device?user_code=UNKNOWN", headers: { "x-forwarded-for": "198.51.100.11" } });
  expect(otherClient.status).toBe(400);
  return { statuses, otherClient: otherClient.status };
});
