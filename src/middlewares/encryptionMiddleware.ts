import { FastifyReply } from "fastify";
import { cryptoLib, logger } from "../lib.js";
import { Request } from "../helpers.js";
export default async function encryptionMiddleware(
  request: Request,
  reply: FastifyReply
) {
  logger.debug(request.encrypted, [
    "encryptionMiddleware",
    request.routeOptions.url ?? "",
    "encrypted",
  ]);
  if (request.routeOptions.url === "/getQueryToken" || !request.encrypted) {
    return;
  }
  if (!request.queryToken) {
    throw new Error("where is queryToken?");
  }

  cryptoLib
    .decryptBuffer(
      request.raw as unknown as ArrayBuffer,
      true,
      request.queryToken
    )
    .then((decrypted) => {
      reply.header("Content-Type", "application/octet-stream");
      request.body = decrypted;
      return;
    })
    .catch((error) => {
      logger.debug(error, [
        "encryptionMiddleware",
        request.routeOptions.url ?? "",
        "encryption error",
      ]);
      return;
    });
}
