import { describe, expect, it } from "vitest";
import { PushRelayConfSchema } from "./push-relay.schemas.ts";

const base = {
  existingSecret: "koan-push-relay",
  apns: { teamId: "TEAM123456", production: { keyId: "ABC123DEFG" } },
  store: { hostPath: "/var/lib/koan-push-relay" },
};

/** The first issue zod raises, for refusals whose wording is zod's own. */
const issue = (conf: object) => PushRelayConfSchema.safeParse({ ...base, ...conf }).error?.issues[0];

describe("PushRelayConfSchema", () => {
  it("fills defaults", () => {
    const c = PushRelayConfSchema.parse(base);
    expect(c.image.repository).toBe("ghcr.io/radiosilence/koan-push-relay");
    expect(c.topic).toBe("cc.blit.koan");
    expect(c.handles).toEqual({ ids: [1], current: 1, lifetimeDays: 60 });
    expect(c.clientIp).toEqual({ header: "x-real-ip", hops: 1 });
  });

  it("wants a gateway key", () => {
    expect(() => PushRelayConfSchema.parse({ ...base, apns: { teamId: "TEAM123456" } })).toThrow(
      "apns.production or apns.sandbox is required",
    );
  });

  it("wants exactly one store, since losing it brings back revoked handles", () => {
    expect(() => PushRelayConfSchema.parse({ ...base, store: {} })).toThrow("exactly one of store.hostPath");
    expect(() => PushRelayConfSchema.parse({ ...base, store: { hostPath: "/var/lib/r", existingClaim: "r" } })).toThrow(
      "exactly one of store.hostPath",
    );
    expect(() => PushRelayConfSchema.parse({ ...base, store: { hostPath: "relay" } })).toThrow(
      "must be an absolute path",
    );
  });

  it("seals with a key it holds", () => {
    expect(() => PushRelayConfSchema.parse({ ...base, handles: { ids: [1], current: 2 } })).toThrow(
      "handles.current must be one of handles.ids",
    );
    expect(() => PushRelayConfSchema.parse({ ...base, handles: { ids: [1, 2], current: 2 } })).not.toThrow();
  });

  it("takes only limits the relay knows, and none it would refuse", () => {
    expect(PushRelayConfSchema.parse({ ...base, limits: { handleAlertsPerHour: 30 } }).limits).toEqual({
      handleAlertsPerHour: 30,
    });
    expect(issue({ limits: { handleAlertPerHour: 30 } })).toMatchObject({
      code: "unrecognized_keys",
      path: ["limits"],
      keys: ["handleAlertPerHour"],
    });
    expect(issue({ limits: { proofsPerSecond: 0 } })).toMatchObject({
      code: "too_small",
      path: ["limits", "proofsPerSecond"],
    });
  });

  it("refuses a lifetime past what the relay accepts, and unknown keys", () => {
    expect(issue({ handles: { lifetimeDays: 400 } })).toMatchObject({
      code: "too_big",
      path: ["handles", "lifetimeDays"],
    });
    expect(issue({ extra: true })).toMatchObject({ code: "unrecognized_keys", path: [], keys: ["extra"] });
  });
});
