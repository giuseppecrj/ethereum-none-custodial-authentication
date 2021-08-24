import { decrypt, encrypt } from './aes-key';
import { hexToUint8Array } from './helpers';

describe('aes key', () => {
  it('should be able to encrypt and decrypt a key', async () => {
    const masterKey = hexToUint8Array(
      '0x95513a464c0d4a7672b49b74d2296ace712dd194ed7db1c3cdf85815b7ec1731'
    );
    const toEncrypt = hexToUint8Array(
      '0x3a6b90c3ba4ef414eba4605ea6b58fc948aa75c68ee7615da0221ac72d1fa53c'
    );
    const iv = hexToUint8Array('0xccc5c4a330a4cbbea1e4e02f6a1f46a9');
    const encrypted = encrypt(toEncrypt, masterKey, iv);
    expect(encrypted).toBeInstanceOf(Uint8Array);

    const decrypted = decrypt(encrypted, masterKey, iv);
    expect(decrypted).toBeInstanceOf(Uint8Array);

    expect(decrypted).toEqual(toEncrypt);
  });
});
