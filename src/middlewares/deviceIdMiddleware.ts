import { Request } from "../helpers.js";
import { prisma, logger } from "../lib.js";
import { FastifyReply } from "fastify";

export default async function deviceIdMiddleware(
  req: Request,
  res: FastifyReply
) {
  logger.debug("", ["deviceIdMiddleware", req.routeOptions.url ?? ""]);

  if (req.encrypted || !req.deviceId) {
    return;
  }
  const device = await prisma.device.findFirst({
    where: { deviceId: req.deviceId },
  });

  if (device && req.ip === device.ip) {
    return;
  }
  logger.debug(`req.ip:${req.ip} device:`, ["deviceIdMiddleware", "reject"]);
  res.statusCode = 403;
  res.send();
}
