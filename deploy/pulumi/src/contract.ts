/**
 * What this package needs from Kubernetes and hands back to whoever deploys it.
 *
 * Declared here rather than imported from a shared package, so the package
 * depends on `@pulumi/*` and `zod` alone and can be deployed by an estate
 * that shares none of its conventions.
 */
import * as z from "zod";

/** Absolute: a relative path resolves against the image's working directory. */
export const AbsolutePath = z.string().startsWith("/", "must be an absolute path");

/** A Kubernetes resource quantity: `500m`, `2`, `64Mi`, `8Gi`. */
export const Quantity = z
  .string()
  .regex(/^\d+(\.\d+)?([munkMGTPE]|[KMGTPE]i)?$/, "must be a Kubernetes quantity, e.g. 500m, 2, 64Mi, 8Gi");

/**
 * A hostname the deployment should publish, and the workload answering it.
 *
 * `service` is a prefix: the Service is `<service>-service`, the convention
 * the deployers of these packages route by.
 */
export type Route = {
  service: string;
  hostname: string;
  paths?: string[];
  priority?: number;
};

/** What the deployer gets back: where this stands. */
export type Deployed = {
  routes: Route[];
};
