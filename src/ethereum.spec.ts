import {
  generatePrivateKey,
  privateKeyToPublicKey,
  recoverPublicKey,
  sign,
} from './ethereum';
import { hexToUint8Array } from './helpers';

describe('ethereum', () => {
  describe('generatePrivateKey', () => {
    it('should generate 32 bytes', () => {
      console;
      expect(generatePrivateKey()).toHaveLength(32);
    });
  });

  describe('privateKeyToPublicKey', () => {
    it('should get back to a public key', () => {
      const privateKey =
        '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8';
      const publicKey = privateKeyToPublicKey(hexToUint8Array(privateKey));

      expect(publicKey).toEqual('0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8');
    });
  });

  describe('sign and recoverPublicKey', () => {
    it('should sign a message and then be able to recover public key', () => {
      const privateKey =
        '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8';
      const message =
        '0x0000000000000000000000000000000000000000000000000000000000000221';
      const signature = sign(privateKey, message);

      expect(signature).toEqual(
        '0x07fabe484fcc6fbdad6939bc00773018e92635e307c08a4f19d5b76498e8b4d17815817b0f224af5a3c96268c35ba20dfbc956e1d63151b74854cc4d9a2a0bd91c'
      );

      const ethereumAddress = recoverPublicKey(signature, message);
      expect(ethereumAddress).toEqual(
        '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8'
      );
    });
  });
});
