import aesjs from 'aes-js';
export type ByteSource = ArrayBuffer | Uint8Array | number[];

export const encrypt = (bytes: ByteSource, key: ByteSource, iv: ByteSource) => {
  const aecCbc = new aesjs.ModeOfOperation.cbc(key, iv);
  return aecCbc.encrypt(bytes);
};

export const decrypt = (bytes: ByteSource, key: ByteSource, iv: ByteSource) => {
  const aecCbc = new aesjs.ModeOfOperation.cbc(key, iv);
  return aecCbc.decrypt(bytes);
};
