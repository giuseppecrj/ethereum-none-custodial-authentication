// bring inhouse!!!
import {
  Address,
  isValidPrivate,
  pubToAddress,
  toBuffer,
  toChecksumAddress,
} from 'ethereumjs-util';
import {
  ecdsaRecover,
  ecdsaSign as secp256k1_sign,
  publicKeyConvert,
} from 'secp256k1';
import {
  addLeading0x,
  generateBytes,
  hexToUnit8Array,
  removeLeading0x,
  toHex,
} from './helpers';

const decompress = (startsWith02Or03: string) => {
  // if already decompressed an not has trailing 04
  const testBuffer = Buffer.from(startsWith02Or03, 'hex');
  if (testBuffer.length === 64) startsWith02Or03 = '04' + startsWith02Or03;

  let decompressed = toHex(
    publicKeyConvert(hexToUnit8Array(startsWith02Or03), false),
    false
  );

  // remove trailing 04
  decompressed = decompressed.substring(2);
  return decompressed;
};

const toAddress = (publicKey: string) => {
  // normalize key
  publicKey = decompress(publicKey);

  const addressBuffer = pubToAddress(toBuffer(addLeading0x(publicKey)));
  const checkSumAdress = toChecksumAddress(
    addLeading0x(addressBuffer.toString('hex'))
  );
  return checkSumAdress;
};

export const generatePrivateKey = () => {
  const pk = generateBytes(32);
  if (!isValidPrivate(Buffer.from(pk))) {
    throw new Error('Private key generated is not valid');
  }

  return pk;
};

export const privateKeyToPublicKey = (privateKey: Uint8Array) => {
  return toChecksumAddress(
    Address.fromPrivateKey(Buffer.from(privateKey)).toString()
  );
};

export const sign = (privateKey: string, hash: string) => {
  hash = addLeading0x(hash);
  if (hash.length !== 66)
    throw new Error('EthCrypto.sign(): Can only sign hashes, given: ' + hash);

  const sigObj = secp256k1_sign(
    new Uint8Array(Buffer.from(removeLeading0x(hash), 'hex')),
    new Uint8Array(Buffer.from(removeLeading0x(privateKey), 'hex'))
  );

  const recoveryId = sigObj.recid === 1 ? '1c' : '1b';

  const newSignature =
    '0x' + Buffer.from(sigObj.signature).toString('hex') + recoveryId;
  return newSignature;
};

export const recoverPublicKey = (signature: string, hash: string) => {
  signature = removeLeading0x(signature);

  // split into v-value and sig
  const sigOnly = signature.substring(0, signature.length - 2); // all but last 2 chars
  const vValue = signature.slice(-2); // last 2 chars

  const recoveryNumber = vValue === '1c' ? 1 : 0;

  let pubKey = toHex(
    ecdsaRecover(
      hexToUnit8Array(sigOnly),
      recoveryNumber,
      hexToUnit8Array(removeLeading0x(hash)),
      false
    ),
    false
  );

  // remove trailing '04'
  pubKey = pubKey.slice(2);

  return toAddress(pubKey);
};
