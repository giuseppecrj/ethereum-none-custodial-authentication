import { randomBytes } from 'crypto';

export const generateBytes = (amount: number): Uint8Array => {
  const b = randomBytes(amount);
  return new Uint8Array(
    b.buffer,
    b.byteOffset,
    b.byteLength / Uint8Array.BYTES_PER_ELEMENT
  );
};

export const toHex = (
  arrayBuffer: WithImplicitCoercion<ArrayBuffer | SharedArrayBuffer>
): string => {
  return '0x' + Buffer.from(arrayBuffer).toString('hex');
};

export const hexToUint8Array = (hex: string): Uint8Array => {
  return new Uint8Array(
    hex
      .replace('0x', '')
      .match(/.{1,2}/g)!
      .map((byte) => parseInt(byte, 16))
  );
};

export const removeLeading0x = (str: string) => {
  if (str.startsWith('0x')) return str.substring(2);
  else return str;
};

export const addLeading0x = (str: string) => {
  if (!str.startsWith('0x')) return '0x' + str;
  else return str;
};

export const uint8ArrayToHex = (arr: Uint8Array) => {
  return Buffer.from(arr).toString('hex');
};

export const hexToUnit8Array = (str: string) => {
  return new Uint8Array(Buffer.from(str, 'hex'));
};
