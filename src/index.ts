import { JwtPayload, verify, Algorithm } from "jsonwebtoken";
import * as express from "express";
import jwksClient from "jwks-rsa";

declare module "express" {
  interface Request {
    user?: JwtPayload;
  }
}
export interface Options {
  issuer: string;
  audience: string;
  algorithms: Algorithm[];
}

const authorize =
  (options: Options) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void | express.Response> => {
    const {
      headers: { authorization: authHeader },
    } = req;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ err: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    const client = jwksClient({
      jwksUri: `${options.issuer}/.well-known/jwks.json`,
    });

    const getKey = (header, callback) => {
      client.getSigningKey(header.kid, (err, key) => {
        const signingKey = key.getPublicKey();
        callback(err, signingKey);
      });
    };

    const verifyToken = async () => {
      return new Promise((resolve, reject) => {
        verify(token, getKey, options, (err, decodedToken) => {
          err ? reject(err) : resolve(decodedToken);
        });
      });
    };

    try {
      const verifiedToken = await verifyToken();
      req.user = verifiedToken;
    } catch (error) {
      return res.status(401).json({ err: error.message });
    }
    next();
  };

export default authorize;
