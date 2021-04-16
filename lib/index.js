"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ValidationError = undefined;

exports.default = function (options = {}) {
  return new Promise((resolve, reject) => {
    let { assertion, appUrl, jwtSecret, findToken, storeToken, aafEnv } = options;
    if (!aafEnv) throw new Error(`Option "aafEnv" is undefined.`);
    if (aafEnv) { aafEnv = aafEnv.toUpperCase(); }
    if (!assertion) throw new Error(`Option "assertion" is undefined.`);
    if (!appUrl) throw new Error(`Option "appUrl" is undefined.`);
    if (!jwtSecret) throw new Error(`Option "jwtSecret" is undefined.`);
    if (!findToken) throw new Error(`Option "findToken" is undefined.`);
    if (!storeToken) throw new Error(`Option "storeToken" is undefined.`);
    if (aafEnv !== "TEST" && aafEnv !== "PRODUCTION") throw new Error(`Option "aafEnv" can only have value "TEST" or  "PRODUCTION".`);

    let jwt = (() => {
      try {
        return (0, _jwtSimple.decode)(assertion, jwtSecret);
      } catch (error) {
        throw new ValidationError("Failed to decode signed JWT.");
      }
    })();

    if (aafEnv === "PRODUCTION" && jwt.iss !== "https://rapid.aaf.edu.au") {
      throw new ValidationError("Invalid JWT issuer.");
    }

    if (aafEnv === "PRODUCTION" && jwt.aud !== appUrl) {
      throw new ValidationError("Invalid JWT audience.");
    }

    Promise.resolve(findToken(jwt.jti)).then(found => {
      if (found) {
        // The same token cannot be used twice.
        throw new ValidationError("Invalid JWT identifier.");
      }

      return storeToken(jwt.jti);
    }).then(() => jwt["https://aaf.edu.au/attributes"]).then(resolve).catch(reject);
  });
};

var _jwtSimple = require("jwt-simple");

class ValidationError extends Error {}

exports.ValidationError = ValidationError;