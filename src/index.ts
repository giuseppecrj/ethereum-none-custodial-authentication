import { toChecksumAddress } from 'ethereumjs-util';
import { decrypt, encrypt } from './aes-key';
import {
  generatePrivateKey,
  privateKeyToPublicKey,
  recoverPublicKey,
  sign,
} from './ethereum';
import {
  generateBytes,
  hexToUint8Array,
  hexToUnit8Array,
  removeLeading0x,
  toHex,
} from './helpers';
import { keccak } from './keccak';
import { generate } from './pbkdf';

export interface EncryptedKeyInfo {
  key: string;
  iv: string;
}

export interface Signature {
  sig: string;
  messageHash: string;
}

const _createSignatureMessageHash = (
  encryptedKeyInfo: EncryptedKeyInfo
): string => {
  return keccak(
    hexToUnit8Array(encryptedKeyInfo.key + removeLeading0x(encryptedKeyInfo.iv))
  );
};

const _createSignature = (
  privateKey: string,
  encryptedKeyInfo: EncryptedKeyInfo
): string => {
  return sign(privateKey, _createSignatureMessageHash(encryptedKeyInfo));
};

export interface DecryptedWallet {
  ethereumAddress: string;
  privateKey: string;
}

export interface EncryptedWallet {
  wallet: DecryptedWallet;
  signature: string;
  // save to the server so you can
  // return this info back to the client
  // so they can decrypt PK if they type this username
  // and password again!
  userAuthenticationToken: string;
  encryptedKeyInfo: EncryptedKeyInfo;
}

export const createWallet = async (
  username: string,
  password: string
): Promise<EncryptedWallet> => {
  const masterKey = await generate(username, password);

  const privateKey = generatePrivateKey();
  const iv = generateBytes(16);
  const encryptedPrivateKey = encrypt(privateKey, masterKey, iv);

  const privateKeyHex = toHex(privateKey);
  const encryptedKeyInfo: EncryptedKeyInfo = {
    key: toHex(encryptedPrivateKey),
    iv: toHex(iv),
  };

  return {
    wallet: {
      ethereumAddress: privateKeyToPublicKey(privateKey),
      privateKey: privateKeyHex,
    },
    signature: _createSignature(privateKeyHex, encryptedKeyInfo),
    userAuthenticationToken: keccak(masterKey),
    encryptedKeyInfo,
  };
};

export const getAuthenticationToken = async (
  username: string,
  password: string
) => {
  const masterKey = await generate(username, password);
  return keccak(masterKey);
};

export const decryptWallet = async (
  username: string,
  password: string,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<DecryptedWallet> => {
  const decryptedWallet = await _decryptWallet(
    username,
    password,
    encryptedKeyInfo
  );

  return {
    ethereumAddress: decryptedWallet.ethereumAddress,
    privateKey: decryptedWallet.privateKey,
  };
};

interface InternalDecryptedWallet extends DecryptedWallet {
  masterKey: Uint8Array;
}

const _decryptWallet = async (
  username: string,
  password: string,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<InternalDecryptedWallet> => {
  const masterKey = await generate(username, password);
  const privateKey = decrypt(
    hexToUint8Array(encryptedKeyInfo.key),
    masterKey,
    hexToUint8Array(encryptedKeyInfo.iv)
  );

  return {
    ethereumAddress: privateKeyToPublicKey(privateKey),
    privateKey: toHex(privateKey),
    masterKey,
  };
};

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

export const changePassword = async (
  username: string,
  passwordInfo: ChangePasswordRequest,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<EncryptedWallet> => {
  const decryptedWallet = await _decryptWallet(
    username,
    passwordInfo.oldPassword,
    encryptedKeyInfo
  );

  const newMasterKey = await generate(username, passwordInfo.newPassword);
  const iv = generateBytes(16);
  const newEncryptedPrivateKey = encrypt(
    hexToUint8Array(decryptedWallet.privateKey),
    newMasterKey,
    iv
  );

  const newEncryptedKeyInfo: EncryptedKeyInfo = {
    key: toHex(newEncryptedPrivateKey),
    iv: toHex(iv),
  };

  return {
    wallet: {
      ethereumAddress: privateKeyToPublicKey(
        hexToUint8Array(decryptedWallet.privateKey)
      ),
      privateKey: decryptedWallet.privateKey,
    },
    signature: _createSignature(
      decryptedWallet.privateKey,
      newEncryptedKeyInfo
    ),
    userAuthenticationToken: keccak(newMasterKey),
    encryptedKeyInfo: newEncryptedKeyInfo,
  };
};

export interface ChangeUsernameRequest {
  oldUsername: string;
  newUsername: string;
}

export const changeUsername = async (
  usernames: ChangeUsernameRequest,
  password: string,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<EncryptedWallet> => {
  const decryptedWallet = await _decryptWallet(
    usernames.oldUsername,
    password,
    encryptedKeyInfo
  );

  const newMasterKey = await generate(usernames.newUsername, password);
  const iv = generateBytes(16);
  const newEncryptedPrivateKey = encrypt(
    hexToUint8Array(decryptedWallet.privateKey),
    newMasterKey,
    iv
  );

  const newEncryptedKeyInfo: EncryptedKeyInfo = {
    key: toHex(newEncryptedPrivateKey),
    iv: toHex(iv),
  };

  return {
    wallet: {
      ethereumAddress: privateKeyToPublicKey(
        hexToUint8Array(decryptedWallet.privateKey)
      ),
      privateKey: decryptedWallet.privateKey,
    },
    signature: _createSignature(
      decryptedWallet.privateKey,
      newEncryptedKeyInfo
    ),
    userAuthenticationToken: keccak(newMasterKey),
    encryptedKeyInfo: newEncryptedKeyInfo,
  };
};

export interface GenerateRecoveryCodeResponse {
  // show this to the user to download or copy
  // this is a way they can recover their account
  // if they forgot their password
  offlineRecoveryCode: string;
  ethereumAddress: string;
  signature: string;
  // save to the server so you can
  // return this info back to the client
  // so they can decrypt PK if they type this username
  // and recovery code again!
  userRecoveryCodeAuthenticationToken: string;
  encryptedKeyInfo: EncryptedKeyInfo;
}

export const generateOfflineRecoveryCode = async (
  username: string,
  password: string,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<GenerateRecoveryCodeResponse> => {
  const decryptedWallet = await _decryptWallet(
    username,
    password,
    encryptedKeyInfo
  );

  const offlineRecoveryCode = toHex(generateBytes(64));
  const recoveryMasterKey = await generate(username, offlineRecoveryCode);

  const iv = generateBytes(16);
  const recoveryEncryptedPrivateKey = encrypt(
    hexToUint8Array(decryptedWallet.privateKey),
    recoveryMasterKey,
    iv
  );

  const recoveryEncryptedKeyInfo: EncryptedKeyInfo = {
    key: toHex(recoveryEncryptedPrivateKey),
    iv: toHex(iv),
  };

  return {
    offlineRecoveryCode,
    ethereumAddress: privateKeyToPublicKey(
      hexToUint8Array(decryptedWallet.privateKey)
    ),
    signature: _createSignature(
      decryptedWallet.privateKey,
      recoveryEncryptedKeyInfo
    ),
    userRecoveryCodeAuthenticationToken: keccak(recoveryMasterKey),
    encryptedKeyInfo: recoveryEncryptedKeyInfo,
  };
};

export const getRecoveryAuthenticationToken = async (
  username: string,
  recoveryCode: string
) => {
  return getAuthenticationToken(username, recoveryCode);
};

export const recoverWithOfflineCode = async (
  username: string,
  recoveryCode: string,
  newPassword: string,
  encryptedKeyInfo: EncryptedKeyInfo
): Promise<EncryptedWallet> => {
  const decryptedWallet = await _decryptWallet(
    username,
    recoveryCode,
    encryptedKeyInfo
  );

  const newMasterKey = await generate(username, newPassword);

  const iv = generateBytes(16);
  const newEncryptedPrivateKey = encrypt(
    hexToUint8Array(decryptedWallet.privateKey),
    newMasterKey,
    iv
  );
  const newEncryptedKeyInfo: EncryptedKeyInfo = {
    key: toHex(newEncryptedPrivateKey),
    iv: toHex(iv),
  };

  return {
    wallet: {
      ethereumAddress: privateKeyToPublicKey(
        hexToUint8Array(decryptedWallet.privateKey)
      ),
      privateKey: decryptedWallet.privateKey,
    },
    signature: _createSignature(
      decryptedWallet.privateKey,
      newEncryptedKeyInfo
    ),
    userAuthenticationToken: keccak(newMasterKey),
    encryptedKeyInfo: newEncryptedKeyInfo,
  };
};

export interface HashAuthenticationTokenOnServerResponse {
  salt: string;
  serverAuthenticationHash: string;
}

export const hashAuthenticationTokenOnServer = async (
  clientAuthenticationToken: string
): Promise<HashAuthenticationTokenOnServerResponse> => {
  const salt = toHex(generateBytes(16));
  const serverAuthenticationHash = await generate(
    salt,
    clientAuthenticationToken
  );

  return {
    salt,
    serverAuthenticationHash: toHex(serverAuthenticationHash),
  };
};

export const generateAuthenticationTokenClientHashOnServer = async (
  userStoredSalt: string,
  clientAuthenticationToken: string
): Promise<string> => {
  return toHex(await generate(userStoredSalt, clientAuthenticationToken));
};

export const serverHashMatchesClientHash = async (
  userStoredSalt: string,
  clientAuthenticationToken: string,
  serverAuthenticationHash: string
): Promise<boolean> => {
  return (
    serverAuthenticationHash ===
    toHex(await generate(userStoredSalt, clientAuthenticationToken))
  );
};

export const verifyEthereumAddress = (
  signature: string,
  encryptedKeyInfo: EncryptedKeyInfo,
  expectedEthereumAddress: string
) => {
  const address = recoverPublicKey(
    signature,
    _createSignatureMessageHash(encryptedKeyInfo)
  );
  return toChecksumAddress(expectedEthereumAddress) === address;
};
