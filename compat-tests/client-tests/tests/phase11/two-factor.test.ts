import { createAuthClient } from "better-auth/client";
import { expect } from "bun:test";
import { twoFactorClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";

function twoFactorActor(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  name = "primary",
) {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [twoFactorClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

function redactTwoFactorPayload<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;
  if (
    clone.data &&
    typeof clone.data === "object" &&
    !Array.isArray(clone.data)
  ) {
    const data = clone.data as Record<string, unknown>;
    if (typeof data.totpURI === "string") {
      data.totpURI = "<totpURI>";
    }
    if (Array.isArray(data.backupCodes)) {
      data.backupCodes = data.backupCodes.map(() => "<backup-code>");
    }
  }
  return clone as T;
}

function decodeBase32(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = secret.toUpperCase().replace(/=+$/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

async function generateCurrentTotp(totpURI: string) {
  const url = new URL(totpURI);
  const secret = url.searchParams.get("secret");
  if (!secret) {
    throw new Error("TOTP URI is missing the secret");
  }

  const digits = Number(url.searchParams.get("digits") ?? "6");
  const period = Number(url.searchParams.get("period") ?? "30");
  const counter = Math.floor(Date.now() / 1000 / period);

  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBytes),
  );
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24)
    | (digest[offset + 1]! << 16)
    | (digest[offset + 2]! << 8)
    | digest[offset + 3]!;

  return String(binary % 10 ** digits).padStart(digits, "0");
}

compatScenario("two-factor enrollment returns URIs and keeps the user disabled until verification", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-enable");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 Enrollment",
  });

  const enable = await client.twoFactor.enable({ password });
  const totp = await client.twoFactor.getTotpUri({ password });
  const session = await client.getSession();

  return {
    enable: ctx.snapshot(redactTwoFactorPayload(enable)),
    totp: ctx.snapshot(redactTwoFactorPayload(totp)),
    session: ctx.snapshot(session),
  };
});

compatScenario("two-factor totp verification enables the user and later sign-in redirects to second factor", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-totp");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 TOTP",
  });

  const enable = await client.twoFactor.enable({ password });
  const code = await generateCurrentTotp(enable.data!.totpURI);
  const verifyTotp = await client.twoFactor.verifyTotp({ code });
  const session = await client.getSession();

  await client.signOut();
  const signIn = await client.signIn.email({
    email,
    password,
    rememberMe: false,
  });

  return {
    verifyTotp: ctx.snapshot(verifyTotp),
    session: ctx.snapshot(session),
    signIn: ctx.snapshot(signIn),
  };
});

compatScenario("two-factor otp flow completes sign-in and rejects requests without the pending cookie", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-otp");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 OTP",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });
  await client.signOut();

  const signIn = await client.signIn.email({
    email,
    password,
    rememberMe: false,
  });
  const sendOtp = await client.twoFactor.sendOtp({});
  const otpRecord = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const unicodeCodes = [];
  for (const zero of [0xff10, 0x1d7ce]) {
    const code = [...otpRecord.otp]
      .map((digit) => String.fromCodePoint(zero + Number(digit)))
      .join("");
    const rejected = await client.twoFactor.verifyOtp({ code });
    expect(rejected.error?.status).toBe(401);
    expect(rejected.error?.code).toBe("INVALID_CODE");
    unicodeCodes.push(ctx.snapshot(rejected));
  }
  const verifyOtp = await client.twoFactor.verifyOtp({ code: otpRecord.otp });
  expect(verifyOtp.error).toBeNull();
  const session = await client.getSession();

  const missingCookieClient = twoFactorActor(ctx, "missing-cookie");
  const missingCookie = await missingCookieClient.twoFactor.verifyOtp({
    code: otpRecord.otp,
  });

  return {
    signIn: ctx.snapshot(signIn),
    sendOtp: ctx.snapshot(sendOtp),
    unicodeCodes,
    verifyOtp: ctx.snapshot(verifyOtp),
    session: ctx.snapshot(session),
    missingCookie: ctx.snapshot(missingCookie),
  };
});

compatScenario("two-factor trusted devices bypass the second-factor challenge on later sign-ins", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-trust");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 Trust Device",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });
  await client.signOut();

  const signIn = await client.signIn.email({
    email,
    password,
  });
  await client.twoFactor.sendOtp({});
  const otpRecord = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verifyOtp = await client.twoFactor.verifyOtp({
    code: otpRecord.otp,
    trustDevice: true,
  });

  await client.signOut();
  const trustedSignIn = await client.signIn.email({
    email,
    password,
  });

  return {
    signIn: ctx.snapshot(signIn),
    verifyOtp: ctx.snapshot(verifyOtp),
    trustedSignIn: ctx.snapshot(trustedSignIn),
  };
});

compatScenario("two-factor OTP enrollment enables OTP without enrolling an authenticator", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-otp-enrollment");
  const password = "password123";
  const signup = await client.signUp.email({ email, password, name: "OTP Enrollment" });
  expect(signup.error).toBeNull();
  const enable = await client.twoFactor.enable({ password, method: "otp" });
  expect(enable.data).toEqual({ method: "otp" });
  const session = await client.getSession();
  expect(session.data?.user.twoFactorEnabled).toBe(true);
  expect(session.data?.session.token).not.toBe(signup.data?.token);
  const totp = await client.twoFactor.getTotpUri({ password });
  expect(totp.error?.code).toBe("TOTP_NOT_ENABLED");
  await client.signOut();
  const challenge = await client.signIn.email({ email, password });
  expect(challenge.data).toEqual({ twoFactorRedirect: true, twoFactorMethods: ["otp"] });
  const sent = await client.twoFactor.sendOtp({});
  expect(sent.error).toBeNull();
  const record = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verified = await client.twoFactor.verifyOtp({ code: record.otp });
  expect(verified.error).toBeNull();
  expect(verified.data?.user.twoFactorEnabled).toBe(true);
  return { enable: ctx.snapshot(enable), totp: ctx.snapshot(totp), challenge: ctx.snapshot(challenge), verified: ctx.snapshot(verified) };
});

compatScenario("two-factor verified enrollment preserves the original authenticator and rotates only the session cookie", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-verified-enrollment");
  const password = "password123";
  const signup = await client.signUp.email({ email, password, name: "Verified Enrollment" });
  expect(signup.error).toBeNull();
  const first = await client.twoFactor.enable({ password });
  const second = await client.twoFactor.enable({ password });
  expect(first.error).toBeNull();
  expect(second.error).toBeNull();
  expect(second.data!.totpURI).not.toBe(first.data!.totpURI);
  const verified = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(second.data!.totpURI) });
  expect(verified.error).toBeNull();
  expect(verified.data?.token).toBe(signup.data?.token);
  expect(verified.data?.user.twoFactorEnabled).toBe(false);
  const session = await client.getSession();
  expect(session.data?.user.twoFactorEnabled).toBe(true);
  expect(session.data?.session.token).not.toBe(verified.data?.token);
  const repeated = await client.twoFactor.enable({ password });
  expect(repeated.error?.code).toBe("TOTP_ALREADY_ENABLED");
  const preserved = await client.twoFactor.getTotpUri({ password });
  expect(preserved.data?.totpURI).toBe(second.data?.totpURI);
  return { verified: ctx.snapshot(verified), repeated: ctx.snapshot(repeated), preserved: ctx.snapshot(redactTwoFactorPayload(preserved)) };
});

compatScenario("two-factor challenge exhaustion and account lockout apply across fresh sign-ins", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-lockout");
  const password = "password123";
  await client.signUp.email({ email, password, name: "Lockout" });
  const enable = await client.twoFactor.enable({ password });
  expect(enable.error).toBeNull();
  const setup = await client.twoFactor.verifyTotp({ code: await generateCurrentTotp(enable.data!.totpURI) });
  expect(setup.error).toBeNull();
  await client.signOut();
  const attempts = [];
  for (let round = 0; round < 2; round++) {
    const challenge = await client.signIn.email({ email, password });
    expect(challenge.data?.twoFactorRedirect).toBe(true);
    for (let attempt = 0; attempt < 5; attempt++) {
      const invalid = await client.twoFactor.verifyBackupCode({ code: "not-a-code" });
      expect(invalid.error?.code).toBe("INVALID_BACKUP_CODE");
      attempts.push(ctx.snapshot(invalid));
    }
    const blocked = await client.twoFactor.verifyBackupCode({ code: "not-a-code" });
    expect(blocked.error?.code).toBe(round === 0 ? "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" : "ACCOUNT_TEMPORARILY_LOCKED");
    attempts.push(ctx.snapshot(blocked));
  }
  await client.signIn.email({ email, password });
  const stillLocked = await client.twoFactor.verifyBackupCode({ code: enable.data!.backupCodes[0]! });
  expect(stillLocked.error?.status).toBe(429);
  expect(stillLocked.error?.code).toBe("ACCOUNT_TEMPORARILY_LOCKED");
  return { attempts, stillLocked: ctx.snapshot(stillLocked) };
});

compatScenario("two-factor OTP attempts consume a code and resend permits a new verification", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-otp-budget");
  const password = "password123";
  await client.signUp.email({ email, password, name: "OTP Budget" });
  expect((await client.twoFactor.enable({ password, method: "otp" })).error).toBeNull();
  await client.signOut();
  await client.signIn.email({ email, password });
  expect((await client.twoFactor.sendOtp({})).error).toBeNull();
  for (let attempt = 0; attempt < 5; attempt++) {
    expect((await client.twoFactor.verifyOtp({ code: "invalid" })).error?.code).toBe("INVALID_CODE");
  }
  const exhausted = await client.twoFactor.verifyOtp({ code: "invalid" });
  expect(exhausted.error?.code).toBe("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
  const consumed = await client.twoFactor.verifyOtp({ code: "invalid" });
  expect(consumed.error?.code).toBe("OTP_HAS_EXPIRED");
  expect((await client.twoFactor.sendOtp({})).error).toBeNull();
  const record = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verified = await client.twoFactor.verifyOtp({ code: record.otp });
  expect(verified.error).toBeNull();
  return { exhausted: ctx.snapshot(exhausted), consumed: ctx.snapshot(consumed), verified: ctx.snapshot(verified) };
});
