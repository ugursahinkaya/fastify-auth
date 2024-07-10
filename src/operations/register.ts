import { prisma, encrypt, logger } from "../lib.js";
import { hashPassword } from "../utils.js";
import {
  RestContext,
  checkParams,
  getOrCreateAccessTokenForLogin,
  getOrCreateDevice,
} from "../helpers.js";

export async function register(
  payload: {
    userName: string;
    firstName: string;
    lastName: string;
    password: string;
    password2: string;
  },
  context: RestContext
) {
  logger.error("", ["register", context.request.routeOptions.url ?? ""]);
  const response = checkParams(payload, context);

  if (response !== true) {
    return response;
  }
  const user = await prisma.user.findFirst({
    where: { userName: payload.userName },
  });

  if (user) {
    return encrypt(
      {
        error: "Kullanıcı zaten kayıtlı",
      },
      context.payload.sender
    );
  }
  if (payload.password !== payload.password2) {
    return encrypt(
      {
        error: "Şifreler eşleşmiyor",
      },
      context.payload.sender
    );
  }
  const newUser = await prisma.user.create({
    data: {
      userName: payload.userName,
      firstName: payload.firstName,
      lastName: payload.lastName,
      password: await hashPassword(payload.password),
    },
  });

  await getOrCreateDevice(context.request);
  const { accessToken, refreshToken } = await getOrCreateAccessTokenForLogin(
    context.request.deviceId,
    newUser.id
  );

  context.reply.cookie("accessToken", accessToken.token, {
    maxAge: 1440000,
    httpOnly: true,
  });

  const { userName, firstName, lastName } = newUser;
  return encrypt(
    { userName, firstName, lastName, refreshToken: refreshToken.token },
    context.payload.sender
  );
}
