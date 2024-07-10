import { prisma, cryptoLib, logger } from "../lib.js";
import {
  RestContext,
  getOrCreateAccessTokenForLogin,
  getOrCreateDevice,
} from "../helpers.js";
export async function getQueryToken(
  payload: { clientPublicKey: string },
  context: RestContext
) {
  logger.debug({ queryToken: context.request.queryToken }, ["getQueryToken"]);
  if (!context.request.queryToken) {
    logger.error("where is queryToken?", ["getQueryToken"]);
    return { error: "" };
  }
  if (!payload.clientPublicKey) {
    logger.error("payload clientPublicKey?", ["getQueryToken"]);
    return { error: "" };
  }
  await cryptoLib.generateKey(context.request.queryToken);
  const buffer = cryptoLib.base64ToArrayBuffer(payload.clientPublicKey);
  await cryptoLib.importPublicKey(buffer, context.request.queryToken!);

  const key = await cryptoLib.exportKey(context.request.queryToken!);
  const publicKey = cryptoLib.arrayBufferToBase64(key);

  if (context.request.userId) {
    logger.debug(context.request.userId, ["getQueryToken", "userId"]);
    const user = await prisma.user.findFirst({
      where: { id: context.request.userId },
      select: {
        firstName: true,
        lastName: true,
        userName: true,
      },
    });

    if (user) {
      logger.debug(user.firstName ?? user.userName, ["getQueryToken", "user"]);
      await prisma.queryToken.update({
        where: { token: context.request.queryToken },
        data: {
          user: { connect: { userName: user.userName } },
        },
      });
      await getOrCreateDevice(context.request);
      const { accessToken } = await getOrCreateAccessTokenForLogin(
        context.request.deviceId,
        context.request.userId
      );
      context.reply.cookie("accessToken", accessToken.token, {
        maxAge: 1440000,
        httpOnly: true,
      });
      context.reply.cookie("queryToken", context.request.queryToken, {
        maxAge: 180000,
        httpOnly: true,
      });
      return {
        serverPublicKey: publicKey,
        queryToken: context.request.queryToken,
        process: "loggedIn",
      };
    }
  }

  const result = {
    serverPublicKey: publicKey,
    process: "loginOrRegister",
  };

  context.reply.cookie("queryToken", context.request.queryToken, {
    maxAge: 180000,
    httpOnly: true,
  });
  logger.debug(result, ["getQueryToken", "result"]);

  return result;
}
