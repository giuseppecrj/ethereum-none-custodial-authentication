import createKeccakHash from 'keccak';

export const keccak = (toHash: Uint8Array) => {
  return (
    '0x' +
    createKeccakHash('keccak256').update(Buffer.from(toHash)).digest('hex')
  );
};
