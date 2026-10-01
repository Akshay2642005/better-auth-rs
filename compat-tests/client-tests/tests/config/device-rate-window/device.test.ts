import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("device guessing window resets after the last allowed request", async (ctx) => {
  const started = performance.now();
  const at = async (milliseconds: number) => {
    await Bun.sleep(Math.max(0, milliseconds - (performance.now() - started)));
  };
  const guess = () => ctx.rawRequest({
    path: "/api/auth/device?user_code=UNKNOWN",
    headers: { "x-forwarded-for": "198.51.100.12" },
  });
  const statuses = [(await guess()).status];
  await at(1300);
  for (let index = 0; index < 4; index++) statuses.push((await guess()).status);
  await at(2200);
  statuses.push((await guess()).status);
  expect(statuses).toEqual([400, 400, 400, 400, 400, 429]);
  await at(3500);
  statuses.push((await guess()).status);
  expect(statuses.at(-1)).toBe(400);
  return statuses;
}, 15000);
