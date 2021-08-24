import { generateBytes, hexToUint8Array, toHex } from './helpers';

describe('helpers', () => {
  describe('generateBytes', () => {
    it('should 16 bytes', () => {
      console;
      expect(generateBytes(16)).toHaveLength(16);
    });

    it('should 32 bytes', () => {
      expect(generateBytes(32)).toHaveLength(32);
    });

    it('should 64 bytes', () => {
      expect(generateBytes(64)).toHaveLength(64);
    });
  });

  describe('toHex', () => {
    it('should convert to hex', () => {
      expect(toHex(generateBytes(16)).includes('0x')).toEqual(true);
    });

    it('should convert to hex', () => {
      expect(
        toHex(
          new Uint8Array([
            28, 209, 85, 192, 92, 147, 183, 53, 106, 71, 158, 215, 29, 214, 182,
            124,
          ])
        )
      ).toEqual('0x1cd155c05c93b7356a479ed71dd6b67c');
    });
  });

  describe('hexToUint8Array', () => {
    it('should convert to uint8array to hex', () => {
      expect(hexToUint8Array('0x1cd155c05c93b7356a479ed71dd6b67c')).toEqual(
        new Uint8Array([
          28, 209, 85, 192, 92, 147, 183, 53, 106, 71, 158, 215, 29, 214, 182,
          124,
        ])
      );
    });
  });
});
