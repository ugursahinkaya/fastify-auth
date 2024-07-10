import queryTokenMiddleware from "./middlewares/queryTokenMiddleware.js";
import { useLogger } from "./lib.js";
import { LogLevel } from "@ugursahinkaya/shared-types";
import { getQueryToken } from "./operations/getQueryToken.js";
import { checkUserName } from "./operations/checkUserName.js";
import { getUserData } from "./operations/getUserData.js";
import { login } from "./operations/login.js";
import { logout } from "./operations/logout.js";
import { refreshToken } from "./operations/refreshToken.js";
import { register } from "./operations/register.js";
import fastifyCookie from "@fastify/cookie";
import { FastifyInstance, FastifyRequest } from "fastify";
import encryptionMiddleware from "./middlewares/encryptionMiddleware.js";
import cookiesMiddleware from "./middlewares/cookiesMiddleware.js";
import { Request, RestContext } from "./helpers.js";
import { IncomingMessage } from "http";

export const operations = {
  checkUserName,
  getQueryToken,
  getUserData,
  login,
  logout,
  refreshToken,
  register,
};
export const middlewares = [
  cookiesMiddleware,
  encryptionMiddleware,
  queryTokenMiddleware,
];

export function contentParser(
  _request: FastifyRequest,
  payload: IncomingMessage,
  done: Function
) {
  const chunks: Uint8Array[] = [];
  const request = _request as Request;
  request.encrypted = true;
  payload.on("data", (chunk) => chunks.push(chunk));
  payload.on("end", () => {
    done(null, Buffer.concat(chunks));
  });
}

export function SecureAuthPlugin(
  fastify: FastifyInstance,
  options: {
    logLevel?: LogLevel;
    websocket?: boolean;
    operations?: Record<
      string,
      (payload: any, context: RestContext | never) => any
    >;
  },
  done: () => void
) {
  useLogger(options.logLevel ?? "error");
  if (options.websocket) {
  }
  fastify.register(fastifyCookie);

  fastify.addContentTypeParser(
    "application/octet-stream",
    (_request, payload, done) => {
      const chunks: Uint8Array[] = [];
      const request = _request as Request;
      request.encrypted = true;
      payload.on("data", (chunk) => chunks.push(chunk));
      payload.on("end", () => {
        done(null, Buffer.concat(chunks));
      });
    }
  );

  middlewares.forEach((middleware) => {
    fastify.addHook(
      "preHandler",
      middleware as (req: FastifyRequest) => ReturnType<typeof middleware>
    );
  });
  const registerOperations = (operationsRecord: Record<string, Function>) => {
    Object.entries(operationsRecord).forEach(([name, operation]) => {
      fastify.post(`/${name}`, async (request, reply) => {
        const res = await operation(request.body, {
          request,
          reply,
          payload: request.raw,
        });
        reply.send(res);
      });
    });
  };
  registerOperations(operations);
  if (options.operations) {
    registerOperations(options.operations);
  }

  done();
}
