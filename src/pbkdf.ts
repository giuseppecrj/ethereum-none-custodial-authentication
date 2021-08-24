import scrypt from 'scrypt-async';

export const generate = async (identifier: string, password: string) => {
  return await new Promise<Uint8Array>((resolve) => {
    scrypt(
      password,
      identifier,
      {
        N: 131072,
        r: 8,
        p: 1,
        dkLen: 32,
      },
      (key) => {
        resolve(key as unknown as Uint8Array);
      }
    );
  });
};
