import { randomString } from "@ugursahinkaya/utils";
import { tomorrow } from "./utils.js";
import { cryptoLib, encrypt, logger, prisma } from "./lib.js";
import { FastifyReply, FastifyRequest } from "fastify";

export type Request = FastifyRequest & {
  deviceId: string;
  queryToken?: string;
  accessToken?: string;
  bearerToken?: string;
  userId?: string;
  encrypted: boolean;
  middlewareIndex: number;
};

export type RestContext = {
  request: Request;
  reply: FastifyReply;
  payload: { sender: string };
};

export function checkParams(payload: any, context: RestContext) {
  if (!context.request) {
    return false;
  }
  if (!payload) {
    return encrypt(
      {
        error: "payload not found",
      },
      context.payload.sender
    );
  }
  if (!context.request) {
    return encrypt(
      {
        error: "context not found",
      },
      context.payload.sender
    );
  }

  const queryToken = context.request.queryToken;
  if (!queryToken) {
    return encrypt(
      {
        error: "queryToken not found",
      },
      context.payload.sender
    );
  }
  return true;
}

export async function checkCookieForQueryToken(req: Request) {
  logger.debug(req.cookies, ["helpers", "checkCookieForQueryToken"]);
  if (!req.cookies["queryToken"]) {
    return false;
  }
  const token = await prisma.queryToken.findFirst({
    include: { device: true },
  });

  if (!token) {
    logger.error(req.cookies["queryToken"], [
      "helpers",
      "checkCookieForQueryToken",
      "token not found",
    ]);
    return false;
  }
  if (token.device?.deviceId !== req.deviceId) {
    logger.error(
      [req.deviceId, token.device?.deviceId],
      ["helpers", "checkCookieForQueryToken", "wrong deviceId"]
    );
    return false;
  }
  req.queryToken = req.cookies["queryToken"];
  return true;
}

export async function getQueryTokenByCookie(req: Request) {
  return await prisma.queryToken.findFirst({
    where: { token: req.cookies["queryToken"] },
  });
}

export async function getOrCreateLoginScope() {
  let loginScope = await prisma.accesScope.findFirst({
    where: {
      name: "User Login",
    },
  });
  if (!loginScope) {
    loginScope = await prisma.accesScope.create({
      data: {
        name: "User Login",
      },
    });
  }
  return loginScope;
}

export async function getOrCreateAccessTokenForLogin(
  deviceId: string,
  userId: string
) {
  let accessToken = await prisma.accessToken.findFirst({
    where: {
      device: { deviceId },
      user: { id: userId },
      name: "userLogin",
    },
  });
  if (accessToken) {
    await prisma.refreshToken.deleteMany({
      where: { accessToken: { id: accessToken.id } },
    });
  }

  let loginScope = await getOrCreateLoginScope();
  if (!accessToken) {
    accessToken = await prisma.accessToken.create({
      data: {
        scope: { connect: { id: loginScope.id } },
        token: randomString(40),
        expiryDate: tomorrow(),
        device: { connect: { id: deviceId } },
        user: { connect: { id: userId } },
        name: "userLogin",
      },
    });
  }

  const refreshToken = await prisma.refreshToken.create({
    data: {
      accessToken: { connect: { id: accessToken.id } },
      token: randomString(40),
    },
  });

  await prisma.device.update({
    where: { deviceId },
    data: {
      accessToken: { connect: { id: accessToken.id } },
      refreshToken: { connect: { id: refreshToken.id } },
    },
  });

  return { accessToken, refreshToken };
}

export async function getOrCreateDevice(req: Request) {
  if (!req.queryToken) {
    return;
  }
  let device = await prisma.device.findFirst({
    where: { queryToken: { some: { token: req.queryToken } } },
  });
  if (!device) {
    device = await prisma.device.create({
      data: {
        queryToken: { connect: { token: req.queryToken } },
        userAgent: req.headers["user-agent"],
        ip: req.ip,
        referer: req.headers.referer,
        deviceId: req.deviceId,
      },
    });
  }

  return device;
}

export async function moveDeviceToNewQueryToken(
  newToken: string,
  deviceId: string,
  oldToken?: string
) {
  try {
    logger.debug({ oldToken, newToken, deviceId }, [
      "helpers",
      "moveDeviceToNewQueryToken",
    ]);
    if (oldToken) {
      await prisma.queryToken.deleteMany({
        where: { token: oldToken },
      });
    }

    const result = await prisma.queryToken.create({
      data: {
        token: newToken,
        device: {
          connectOrCreate: { where: { deviceId }, create: { deviceId } },
        },
      },
    });
    logger.debug(result, ["helpers", "moveDeviceToNewQueryToken", "result"]);
    return result;
  } catch (err) {
    console.log(err);
    return;
  }
}
function moveCryptoKeysToNewQueryToken(oldToken: string, newToken: string) {
  logger.debug({ oldToken, newToken }, [
    "helpers",
    "moveCryptoKeysToNewQueryToken",
  ]);
  const secret = cryptoLib.keyMap.get(`${oldToken}SCR`);
  if (secret) {
    cryptoLib.keyMap.set(`${newToken}SCR`, secret);
    cryptoLib.keyMap.delete(`${oldToken!}SCR`);
  }
}

export async function renewQueryToken(req: Request, res: FastifyReply) {
  const newToken = randomString(40);
  const oldToken = req.queryToken;
  logger.debug(newToken, ["helpers", "renewQueryToken", "start"]);

  if (oldToken) {
    moveCryptoKeysToNewQueryToken(oldToken, newToken);
  }
  logger.debug(newToken, ["helpers", "renewQueryToken", "new token"]);
  req.queryToken = newToken;

  res.cookie("queryToken", newToken, {
    maxAge: 180000,
    httpOnly: true,
  });
  const newTokenRes = await moveDeviceToNewQueryToken(
    newToken,
    req.deviceId,
    oldToken
  );

  return newTokenRes;
}
