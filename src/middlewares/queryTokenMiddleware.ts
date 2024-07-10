import {
  checkCookieForQueryToken,
  renewQueryToken,
  Request,
} from "../helpers.js";
import { logger } from "../lib.js";
import { FastifyReply } from "fastify";
export default async function queryTokenMiddleware(
  request: Request,
  reply: FastifyReply
) {
  logger.debug("", ["queryTokenMiddleware", request.routeOptions.url ?? ""]);

  if (request.routeOptions.url === "/getQueryToken") {
    await renewQueryToken(request, reply);
    return;
  }
  if (!request.encrypted) {
    return;
  }
  if (
    request.routeOptions.url !== "/getQueryToken" &&
    !(await checkCookieForQueryToken(request))
  ) {
    logger.error("queryToken cookie not provided or corrupted", [
      "queryTokenMiddleware",
      request.routeOptions.url ?? "",
    ]);
    reply.statusCode = 403;
    reply.send();
  }

  await renewQueryToken(request, reply);

  return;
}
