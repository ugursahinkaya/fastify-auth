import { FastifyReply } from "fastify";
import { Request } from "../helpers.js";
import { logger } from "../lib.js";

export default function cookiesMiddleware(
  request: Request,
  _res: FastifyReply,
  done: Function
) {
  logger.debug("", ["cookiesMiddleware", request.routeOptions.url ?? ""]);

  if (request.cookies["deviceId"]) {
    request.deviceId = request.cookies["deviceId"];
  }
  if (request.cookies["queryToken"]) {
    request.queryToken = request.cookies["queryToken"];
  }
  if (request.cookies["accessToken"]) {
    request.accessToken = request.cookies["accessToken"];
  }
  done();
}
