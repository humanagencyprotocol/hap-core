/**
 * Error type of the device-keys module.
 *
 * @experimental The protocol does not define device enrolment yet. Names, shapes and
 * behaviour of everything in `device-keys` may change in any release.
 */

/** A refusal. `code` is the stable name (MALFORMED, WRONG_ROOT, BAD_SEQ, ...). @experimental */
export class DeviceKeysError extends Error {
  readonly code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = 'DeviceKeysError';
    this.code = code;
  }
}

/** Throw a DeviceKeysError. @experimental */
export function fail(code: string, message?: string): never {
  throw new DeviceKeysError(code, message);
}
