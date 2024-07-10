import { prisma, encrypt, logger } from "../lib.js";
import { verifyPassword } from "../utils.js";
import {
  RestContext,
  checkParams,
  getOrCreateAccessTokenForLogin,
  getOrCreateDevice,
} from "../helpers.js";

export async function login(
  payload: { userName: string; password: string },
  context: RestContext
) {
  logger.debug(payload.userName, [
    "login",
    context.request.routeOptions.url ?? "",
  ]);

  const response = checkParams(payload, context);
  if (response !== true) {
    return response;
  }
  const queryToken = context.request.queryToken!;
  const user = await prisma.user.findFirst({
    where: { userName: payload.userName },
  });
  if (!user) {
    return encrypt(
      {
        error: "Kullanıcı bulunamadı",
      },
      queryToken
    );
  }

  const valid = await verifyPassword(payload.password, user.password);
  if (!valid) {
    logger.error("Hatalı kullanıcı bilgileri", [
      "login",
      context.request.routeOptions.url ?? "",
    ]);

    return encrypt(
      {
        error: "Hatalı telefon numarası ya da şifre",
      },
      queryToken
    );
  }

  await getOrCreateDevice(context.request);
  const { accessToken, refreshToken } = await getOrCreateAccessTokenForLogin(
    context.request.deviceId,
    user.id
  );
  context.reply.cookie("accessToken", accessToken.token, {
    maxAge: 1440000,
    httpOnly: true,
  });
  const { userName, firstName, lastName } = user;

  await prisma.user.update({
    where: { id: user.id },
    data: {
      queryToken: { connect: { token: queryToken } },
    },
  });
  logger.debug("Logged in", ["login", context.request.routeOptions.url ?? ""]);
  return encrypt(
    {
      userName,
      firstName,
      lastName,
      refreshToken: refreshToken?.token,
      queryToken,
      process: "loggedIn",
    },
    queryToken
  );
}
