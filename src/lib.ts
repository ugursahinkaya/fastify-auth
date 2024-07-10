import { PrismaClient } from "./auth-client/index.js";
import { checkUserName } from "./operations/checkUserName.js";
import { getQueryToken } from "./operations/getQueryToken.js";
import { login } from "./operations/login.js";
import { logout } from "./operations/logout.js";

import { register } from "./operations/register.js";
import { getUserData } from "./operations/getUserData.js";
import { refreshToken } from "./operations/refreshToken.js";
import { CryptoLib } from "@ugursahinkaya/crypto-lib";
import { Logger } from "@ugursahinkaya/logger";
import { LogLevel } from "@ugursahinkaya/shared-types";

export let logger: Logger;
export function useLogger(logLevel?: LogLevel) {
  logger = new Logger("auth-middleware", "#EE7733", logLevel);
}

export const cryptoLib = new CryptoLib();
export async function encrypt(data: Record<string, any>, receiver: string) {
  try {
    const [ciphertext, iv] = await cryptoLib.encrypt(
      JSON.stringify(data),
      receiver
    );
    const concatenatedArray = new Uint8Array(
      iv.byteLength + ciphertext.byteLength
    );
    concatenatedArray.set(new Uint8Array(iv), 0);
    concatenatedArray.set(new Uint8Array(ciphertext), iv.byteLength);

    return Buffer.from(concatenatedArray);
  } catch {
    return data;
  }
}
export const prisma = new PrismaClient();
export const operations = {
  checkUserName,
  getQueryToken,
  login,
  logout,
  register,
  getUserData,
  refreshToken,
};
