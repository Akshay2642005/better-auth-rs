import { expect, test } from "bun:test";
import { createTracingFetch, type TraceEntry } from "./trace";

test("raw traces retain cookie domains that affect browser acceptance", async () => {
  const server = Bun.serve({
    port: 0,
    fetch: () => new Response("{}", {
      headers: {
        "content-type": "application/json",
        "set-cookie": "session=secret; Path=/; HttpOnly; Domain=attacker.test",
      },
    }),
  });
  try {
    const traces: TraceEntry[] = [];
    await createTracingFetch(server.url.origin, "test", traces)(server.url);
    expect(traces[0]?.responseCookies.session).toMatchObject({ domain: "attacker.test" });
  } finally {
    server.stop(true);
  }
});
