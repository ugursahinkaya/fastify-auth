import { cryptoLib, encrypt, logger, prisma } from "../lib.js";
import { RestContext, checkParams } from "../helpers.js";

export async function logout(payload: {}, context: RestContext) {
  logger.debug("", ["logout", context.request.routeOptions.url ?? ""]);

  context.reply.clearCookie("accessToken");
  const response = checkParams(payload, context);
  if (response !== true) {
    return response;
  }
  context.reply.clearCookie("queryToken");
  cryptoLib.keyMap.delete(`${context.request.cookies["queryToken"]!}SCR`);
  const queryToken = context.request.queryToken!;
  const token = await prisma.queryToken.findFirst({
    where: { token: queryToken },
    include: { device: true },
  });
  if (!token || !token.device) {
    logger.error("Unexpected error", [
      "logout",
      context.request.routeOptions.url ?? "",
    ]);

    return encrypt(
      {
        error: "Unexpected error",
      },
      context.payload.sender
    );
  }
  await prisma.device.update({
    where: { id: token.device.id },
    data: { queryToken: { disconnect: { id: token.id } } },
  });
  await prisma.queryToken.delete({
    where: { id: token.id },
  });
  logger.debug("Logged out", [
    "logout",
    context.request.routeOptions.url ?? "",
  ]);

  return encrypt({ process: "loggedOut" }, context.payload.sender);
}
