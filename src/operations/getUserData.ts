import { prisma, encrypt, logger } from "../lib.js";
import { RestContext, checkParams } from "../helpers.js";

export async function getUserData(
  payload: { userQueryToken: string },
  context: RestContext
) {
  logger.debug(payload, [
    "getUserData",
    context.request.routeOptions.url ?? "",
  ]);
  const response = checkParams(payload, context);
  if (response !== true) {
    return response;
  }
  if (!context.request.accessToken) {
    return encrypt(
      {
        error: "accessToken must provide",
      },
      context.payload.sender
    );
  }
  const accessToken = await prisma.accessToken.findFirst({
    where: { token: context.request.accessToken },
    select: {
      scope: true,
    },
  });
  if (!accessToken || accessToken.scope?.name !== "Socket Server") {
    return encrypt(
      {
        error: "invalid accessToken",
      },
      context.request.queryToken!
    );
  }
  const queryToken = await prisma.queryToken.findFirst({
    where: { token: payload.userQueryToken },
    select: {
      device: true,
      id: true,
    },
  });

  if (!queryToken?.device) {
    return encrypt(
      {
        error: "user not Found",
      },
      context.request.queryToken!
    );
  }
  const user = await prisma.user.findFirst({
    where: { queryToken: { some: { id: queryToken.id } } },
  });

  if (!user) {
    return encrypt(
      {
        error: "user not Found",
      },
      context.request.queryToken!
    );
  }
  const { firstName, lastName, userName } = user;
  return encrypt(
    { firstName, lastName, userName },
    context.request.queryToken!
  );
}
