import { Algorithm } from "jsonwebtoken";
import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: ["RS256"] as Algorithm[],
};
const currentTime = Math.round(Date.now() / 1000);
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
};

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  test("should add a user object containing the token claims to the request and delegate to the next middleware", async () => {
    const res = createResponse();
    const next = jest.fn();

    const token = await tokenGenerator.createSignedJWT(claims);

    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);
    expect(req).toHaveProperty("user", claims);
    expect(next).toHaveBeenCalled;
  });
});

describe("A request with an invalid auth header", () => {
  test("should respond with a 401, an 'Unauthorized' error message and then end the req-res cycle ", async () => {
    const res = createResponse();
    const next = jest.fn();

    const req = createRequest({
      headers: {
        Authorization: "Bear token",
      },
    });

    await authorise(options)(req, res, next);

    const JSONData = res._getJSONData();
    expect(JSONData).toHaveProperty("err", "Unauthorized");
    expect(res.statusCode).toEqual(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("A request with an expired token ", () => {
  test("should respond with a 401 code, a relevant error message, and then end the req-res cycle", async () => {
    const res = createResponse();
    const next = jest.fn();

    const expiredClaims = { ...claims, exp: currentTime - 10 };
    const token = await tokenGenerator.createSignedJWT(expiredClaims);

    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    const JSONData = res._getJSONData();
    expect(JSONData).toHaveProperty("err", "jwt expired");
    expect(res.statusCode).toEqual(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("A request with a malformed token", () => {
  test("should fail to validate and respond with a 401 code", async () => {
    const res = createResponse();
    const next = jest.fn();

    const token = "token";

    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    const JSONData = res._getJSONData();
    expect(JSONData).toHaveProperty("err", "jwt malformed");
    expect(res.statusCode).toEqual(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("A request with an invalid audience", () => {
  test("should fail to validate and respond with a 401 code", async () => {
    const res = createResponse();
    const next = jest.fn();

    const newClaims = {
      ...claims,
      aud: "xyz",
    };

    const token = await tokenGenerator.createSignedJWT(newClaims);

    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    const JSONData = res._getJSONData();
    expect(JSONData).toHaveProperty(
      "err",
      `jwt audience invalid. expected: ${options.audience}`
    );
    expect(res.statusCode).toEqual(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("A request with an invalid issuer", () => {
  test("should fail to validate and respond with a 401 code", async () => {
    const res = createResponse();
    const next = jest.fn();

    const newClaims = {
      ...claims,
      iss: "iss",
    };

    const token = await tokenGenerator.createSignedJWT(newClaims);

    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    const JSONData = res._getJSONData();
    expect(JSONData).toHaveProperty(
      "err",
      `jwt issuer invalid. expected: ${options.issuer}`
    );
    expect(res.statusCode).toEqual(401);
    expect(next).not.toHaveBeenCalled();
  });
});
