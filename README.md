# TITLE_OF_PACKAGE!!

Encryption is scary and hard, knowing your doing the correct things with certain keys is hard to know. Also on top of this the mass amount of ethereum wallets sometimes add bad UX/UI and disjoint the user from your dApps, you may want to create a more integrated approach. On top of this, this package follows a web2 approach of a standard username and password making it simple for the user to use your application. Also creating something which is fully onchain is expensive currently due to transaction per each save state and encrypted keys themselives should be protected at least from people being able to just get a list and try to brute force it. This is a way you can do best of both worlds without you holding anyone's keys.

The aim of this package is to abstract all this :head_bandage: away for you and give you simple tools to allow you to create none custodial ethereum wallet logins, without worrying about how the encryption links together or the scary thought of saving peoples private keys.

All the decryption will happen on the client side and you will just need a server which stores the encrypted data and returns it. All of this data is useless without the keys generated client side.

Just to note using this kind of encryption is as safe as the username and password the user gives. The package does not force max contraints on the usage, it is up to you to decide how you want to force the user to make sure they enter a strong password and username. We strongly advise you force a strong password on creation of wallets to protect your user. We would not promote this approach for long term storing of crypto either, you can see this logic more as a hot/burner wallet aka your users can use this to interact with your dApp easily and safely. Supporting them without an extension just the native browser.

This model is based on the same model `LastPass` use for their none custodial password manager. It is also heavily influenced by how the none custodial `FunWallet` works.

## Install package

### NPM

```bash
$ npm install PACKAGE_NAME
```

### YARN

```bash
$ yarn PACKAGE_NAME
```

## Usage and flows

This will walk you through the usage of the package with flow diagrams explaining the flows.

### New wallet

Creating a new user.

#### Flow

![create wallet flow](sequences/1.create-wallet.svg)

Code example this includes client + server.

##### Client

```ts
import { createNewWallet } from 'ethereum-web2-encryption';

// They have just clicked the register button after entering
// their username and password
export const register = async (username: string, password: string) => {
  const encryptedWallet = await createWallet(username, password);
  console.log(encryptedWallet);
  // {
  //    wallet: {
  //        ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //        privateKey: '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8',
  //    },
  //    signature: '0xf09eb344c7cbe4aebd7c3d2109eeddd5a3f1ec6a445a26ed1c46f47bce902a274af03b86f19557026055467a796a7e76be4c1fdd19132fd102097abe3124af081c',
  //    userAuthenticationToken: '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7',
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  const request = {
    username,
    ethereumAddress: encryptedWallet.ethereumAddress,
    signature: encryptedWallet.signature,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
    encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
  };

  // look at server part below to see what your server is expected to do
  await fetch('YOUR_SERVER_API_REGISTER_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  // done user is registered!
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface RegisterRequest {
  username: string;
  ethereumAddress: string;
  signature: string;
  userAuthenticationToken: string;
  encryptedKeyInfo: {
    key: string;
    iv: string;
  };
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const register = async (registerInfo: RegisterRequest) => {
  const userExists = await db.userExists(registerInfo.username);
  if (userExists) {
    throw new Error('Username already exists');
  }

  const ethereumAddressExists = await db.ethereumAddressExists(
    registerInfo.ethereumAddress
  );
  if (ethereumAddressExists) {
    throw new Error('Ethereum address already exists');
  }

  const ownsEthereumAddress = await verifyEthereumAddress(
    registerInfo.signature,
    registerInfo.encryptedKeyInfo,
    registerInfo.ethereumAddress
  );
  if (!ownsEthereumAddress) {
    throw new Error(
      'You do not own the ethereum address so can not register you'
    );
  }

  const serverAuthHashResult = await hashAuthenticationTokenOnServer(
    registerInfo.userAuthenticationToken
  );

  await db.createNewUser({
    username: registerInfo.username,
    ethereumAddress: registerInfo.ethereumAddress,
    serverAuthenticationHash: serverAuthHashResult.serverAuthenticationHash,
    salt: serverAuthHashResult.salt,
    encryptedPk: registerInfo.encryptedKeyInfo.key,
    encryptedPkIv: registerInfo.encryptedKeyInfo.iv,
  });

  // done user is registered!
};
```

### Login existing wallet

User logging into an already created account.

#### Flow

![login flow](sequences/2.login.svg)

##### Client

```ts
import {
  getAuthenticationToken,
  decryptWallet,
} from 'ethereum-web2-encryption';

// They have just clicked the login button after entering
// their username and password
export const login = async (username: string, password: string) => {
  const authenticationToken = await getAuthenticationToken(username, password);

  const request = {
    username,
    userAuthenticationToken: authenticationToken,
  };

  // look at server part below to see what your server is expected to do
  const response = await fetch('YOUR_SERVER_API_LOGIN_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  const encryptedKeyInfo = await response.json();
  console.log(encryptedKeyInfo);
  // {
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  const decryptedWallet = await decryptWallet(
    username,
    password,
    encryptedKeyInfo
  );
  console.log(decryptedWallet);
  // {
  //    ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //    privateKey: '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8',
  //}

  // done user is logged in!
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface LoginRequest {
  username: string;
  userAuthenticationToken: string;
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const login = async (loginRequest: LoginRequest) => {
  const userAuthenticationInfo = await db.userAuthenticationInfo(
    registerInfo.username
  );
  if (!userAuthenticationInfo) {
    throw new Error('User does not exists');
  }

  const serverHashMatchesClientHash = await serverHashMatchesClientHash(
    userAuthenticationInfo.salt,
    loginRequest.userAuthenticationToken,
    userAuthenticationInfo.serverAuthenticationHash
  );
  console.log(serverHashMatchesClientHash);
  // {
  //    salt: '0x2e7199cd889426be35d730aabc3fa073',
  //    serverAuthenticationHash: '0xf06e83e0086d2546cc7730eeee08bc739daa2af80fb34691ebc0a0964b96eb34',
  //}
  if (!serverHashMatchesClientHash) {
    throw new Error('Incorrect login.');
  }

  return {
    encryptedKeyInfo: {
      key: userAuthenticationInfo.encryptedPk,
      iv: userAuthenticationInfo.encryptedPkIv,
    },
  };
};
```

### Change password

#### Flow

![change password flow](sequences/3.change-password.svg)

##### Client

```ts
import {
  getAuthenticationToken,
  changePassword,
} from 'ethereum-web2-encryption';

// They have just clicked the change password and entered their username and password
// to confirm they want to do it
export const getEncryptedInformation = async (
  username: string,
  password: string
) => {
  const authenticationToken = await getAuthenticationToken(username, password);

  const request = {
    username,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
  };

  // look at server part below to see what your server is expected to do
  const response = await fetch('YOUR_SERVER_API_GET_ENCRYPTED_INFO_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  const encryptedKeyInfo = await response.json();
  console.log(encryptedKeyInfo);
  // {
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // the user now needs to enter their new password, you should hold the
  // the encryptedKeyInfo somewhere ready for the next method below
  // below method should show you what the next steps are
};

interface ChangePassword {
  username: string;
  oldPassword: string;
  newPassword: string;
  encryptedKeyInfo: { key: string; iv: string };
}

// They have just clicked entered their new password and pressed enter
export const changePassword = async (changePasswordRequest: ChangePassword) => {
  const authenticationToken = await getAuthenticationToken(
    changePasswordRequest.username,
    changePasswordRequest.newPassword
  );

  const encryptedWallet = await changePassword(
    changePasswordRequest.username,
    {
      oldPassword: changePasswordRequest.oldPassword,
      newPassword: changePasswordRequest.newPassword,
    },
    changePasswordRequest.encryptedKeyInfo
  );
  console.log(encryptedWallet);
  // {
  //    wallet: {
  //        ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //        privateKey: '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8',
  //    },
  //    signature: '0xf09eb344c7cbe4aebd7c3d2109eeddd5a3f1ec6a445a26ed1c46f47bce902a274af03b86f19557026055467a796a7e76be4c1fdd19132fd102097abe3124af081c',
  //    userAuthenticationToken: '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7',
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // TODO LOOK AT FLOW OF PASSING OLD AUTHENTICATION TOKEN IN?!?!
  const request = {
    username,
    ethereumAddress: encryptedWallet.ethereumAddress,
    signature: encryptedWallet.signature,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
    encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
  };
  // look at server part below to see what your server is expected to do
  await fetch('YOUR_SERVER_API_CHANGE_PASSWORD_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  // change password is done!
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
  serverHashMatchesClientHash,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface EncryptedInfoRequest {
  username: string;
  userAuthenticationToken: string;
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const encryptedInfo = async (
  encryptedInfoRequest: EncryptedInfoRequest
) => {
  const encryptedInfo = await db.userAuthenticationInfo(
    encryptedInfoRequest.username
  );
  if (!encryptedInfo) {
    throw new Error('User does not exists');
  }

  const serverHashMatchesClientHash = await serverHashMatchesClientHash(
    encryptedInfo.salt,
    encryptedInfoRequest.userAuthenticationToken,
    encryptedInfo.serverAuthenticationHash
  );
  if (!serverHashMatchesClientHash) {
    throw new Error(
      '401 > this does not match the user auth token (wrong username + password).'
    );
  }

  return {
    encryptedKeyInfo: {
      key: userAuthenticationInfo.encryptedPk,
      iv: userAuthenticationInfo.encryptedPkIv,
    },
  };
};

interface ChangePasswordRequest {
  username: string;
  ethereumAddress: string;
  signature: string;
  userAuthenticationToken: string;
  encryptedKeyInfo: {
    key: string;
    iv: string;
  };
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const changePassword = async (
  changePasswordInfo: ChangePasswordRequest
) => {
  const userExists = await db.userExists(changePasswordInfo.username);
  if (!userExists) {
    throw new Error('Username doesnt exists');
  }

  const ownsEthereumAddress = await verifyEthereumAddress(
    changePasswordInfo.signature,
    changePasswordInfo.encryptedKeyInfo,
    changePasswordInfo.ethereumAddress
  );
  if (!ownsEthereumAddress) {
    throw new Error(
      'You do not own the ethereum address so can not register you'
    );
  }

  const serverAuthHashResult = await hashAuthenticationTokenOnServer(
    changePasswordInfo.userAuthenticationToken
  );
  console.log(serverAuthHashResult);
  // {
  //    salt: '0x2e7199cd889426be35d730aabc3fa073',
  //    serverAuthenticationHash: '0xf06e83e0086d2546cc7730eeee08bc739daa2af80fb34691ebc0a0964b96eb34',
  //}

  await db.updateUser({
    username: changePasswordInfo.username,
    serverAuthenticationHash: serverAuthHashResult.serverAuthenticationHash,
    salt: serverAuthHashResult.salt,
    encryptedPk: changePasswordInfo.encryptedKeyInfo.key,
    encryptedPkIv: changePasswordInfo.encryptedKeyInfo.iv,
  });

  // done user has changed password!
};
```

### Change username

#### Flow

![change username flow](sequences/4.change-username.svg)

##### Client

```ts
import {
  getAuthenticationToken,
  changeUsername,
} from 'ethereum-web2-encryption';

// They have just clicked the change password and entered their username and password
// to confirm they want to do it
export const getEncryptedInformation = async (
  username: string,
  password: string
) => {
  const authenticationToken = await getAuthenticationToken(username, password);

  const request = {
    username,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
  };

  // look at server part below to see what your server is expected to do
  const response = await fetch('YOUR_SERVER_API_GET_ENCRYPTED_INFO_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  const encryptedKeyInfo = await response.json();
  console.log(encryptedKeyInfo);
  // {
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // the user now needs to enter their new password, you should hold the
  // the encryptedKeyInfo somewhere ready for the next method below
  // below method should show you what the next steps are
};

interface ChangeEmailRequest {
  oldUsername: string;
  newUsername: string;
  password: string;
  encryptedKeyInfo: { key: string; iv: string };
}

// They have just clicked change email entered their new password and pressed enter
export const changeEmail = async (changeEmailRequest: ChangeEmailRequest) => {
  const authenticationToken = await getAuthenticationToken(
    changeEmailRequest.oldUsername,
    changeEmailRequest.newPassword
  );

  const encryptedWallet = await changeUsername(
    {
      oldUsername: changeEmailRequest.oldUsername,
      newUsername: changeEmailRequest.newUsername,
    },
    changeEmailRequest.password,
    changeEmailRequest.encryptedKeyInfo
  );
  console.log(encryptedWallet);
  // {
  //    wallet: {
  //        ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //        privateKey: '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8',
  //    },
  //    signature: '0xf09eb344c7cbe4aebd7c3d2109eeddd5a3f1ec6a445a26ed1c46f47bce902a274af03b86f19557026055467a796a7e76be4c1fdd19132fd102097abe3124af081c',
  //    userAuthenticationToken: '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7',
  //    encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // TODO LOOK AT FLOW OF PASSING OLD AUTHENTICATION TOKEN IN?!?!
  const request = {
    oldUsername,
    newUsername,
    ethereumAddress: encryptedWallet.ethereumAddress,
    signature: encryptedWallet.signature,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
    encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
  };
  // look at server part below to see what your server is expected to do
  await fetch('YOUR_SERVER_API_CHANGE_USERNAME_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  // change username is done!
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
  serverHashMatchesClientHash,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface EncryptedInfoRequest {
  username: string;
  userAuthenticationToken: string;
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const encryptedInfo = async (
  encryptedInfoRequest: EncryptedInfoRequest
) => {
  const encryptedInfo = await db.userAuthenticationInfo(
    encryptedInfoRequest.username
  );
  if (!encryptedInfo) {
    throw new Error('User does not exists');
  }

  const serverHashMatchesClientHash = await serverHashMatchesClientHash(
    encryptedInfo.salt,
    encryptedInfoRequest.userAuthenticationToken,
    encryptedInfo.serverAuthenticationHash
  );
  if (!serverHashMatchesClientHash) {
    throw new Error(
      '401 > this does not match the user auth token (wrong username + password).'
    );
  }

  return {
    encryptedKeyInfo: {
      key: userAuthenticationInfo.encryptedPk,
      iv: userAuthenticationInfo.encryptedPkIv,
    },
  };
};

interface ChangeUsernameRequest {
  oldUsername: string;
  newUsername: string;
  ethereumAddress: string;
  signature: string;
  userAuthenticationToken: string;
  encryptedKeyInfo: {
    key: string;
    iv: string;
  };
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const changeUsername = async (
  changeUsernameInfo: ChangeUsernameRequest
) => {
  const userExists = await db.userExists(changeUsernameInfo.oldUsername);
  if (!userExists) {
    throw new Error('Username does not exists');
  }

  const newUserExists = await db.userExists(changeUsernameInfo.newUsername);
  if (newUserExists) {
    throw new Error('Username already exists');
  }

  const ownsEthereumAddress = await verifyEthereumAddress(
    changeUsernameInfo.signature,
    changeUsernameInfo.encryptedKeyInfo,
    changeUsernameInfo.ethereumAddress
  );
  if (!ownsEthereumAddress) {
    throw new Error(
      'You do not own the ethereum address so can not register you'
    );
  }

  const serverAuthHashResult = await hashAuthenticationTokenOnServer(
    changeUsernameInfo.userAuthenticationToken
  );
  console.log(serverAuthHashResult);
  // {
  //    salt: '0x2e7199cd889426be35d730aabc3fa073',
  //    serverAuthenticationHash: '0xf06e83e0086d2546cc7730eeee08bc739daa2af80fb34691ebc0a0964b96eb34',
  //}

  await db.updateUser({
    oldUsername: changeUsernameInfo.oldUsername,
    newUsername: changeUsernameInfo.newUsername,
    serverAuthenticationHash: serverAuthHashResult.serverAuthenticationHash,
    salt: serverAuthHashResult.salt,
    encryptedPk: changeUsernameInfo.encryptedKeyInfo.key,
    encryptedPkIv: changeUsernameInfo.encryptedKeyInfo.iv,
  });

  // done user has changed username!
};
```

### Recovery

Ability to recover is critical on something which holds real funds. This exposes some easy to call methods to allow you to support this but still remain none custodial.

#### Generated offline recovery code

##### Flow

![generate recovery offline code flow](sequences/5.generate-offline-recovery-code.svg)

##### Client

```ts
import {
  getAuthenticationToken,
  generateOfflineRecoveryCode,
} from 'ethereum-web2-encryption';

// They have just clicked the change password and entered their username and password
// to confirm they want to do it
export const getEncryptedInformation = async (
  username: string,
  password: string
) => {
  const authenticationToken = await getAuthenticationToken(username, password);

  const request = {
    username,
    userAuthenticationToken: encryptedWallet.userAuthenticationToken,
  };

  // look at server part below to see what your server is expected to do
  const response = await fetch('YOUR_SERVER_API_GET_ENCRYPTED_INFO_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  const encryptedKeyInfo = await response.json();
  console.log(encryptedKeyInfo);
  // {
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // the user now needs to enter their new password, you should hold the
  // the encryptedKeyInfo somewhere ready for the next method below
  // below method should show you what the next steps are
};

interface GenerateOfflineRecoveryCodeRequest {
  username: string;
  password: string;
  encryptedKeyInfo: { key: string; iv: string };
}

// They have just clicked change email entered their new password and pressed enter
export const generateOfflineRecoveryCode = async (
  offlineRecoveryRequest: GenerateOfflineRecoveryCodeRequest
) => {
  const authenticationToken = await getAuthenticationToken(
    offlineRecoveryRequest.username,
    offlineRecoveryRequest.password
  );

  const generateRecoveryCodeResponse = await generateOfflineRecoveryCode(
    offlineRecoveryRequest.username,
    offlineRecoveryRequest.password,
    offlineRecoveryRequest.encryptedKeyInfo
  );
  console.log(generateRecoveryCodeResponse);
  // {
  //    offlineRecoveryCode: {
  //       userCode: '0x975d73660b0b2fc1823668769ba0a88ba3d39eece71d15abc25c2fd2e95f042822f85bba3fb98b3d6d7aea326e361ba5a12c494a2ef33d05e1617adb5e26a0e6362bd43d7da0a0e4963fbde594b3b9ed',
  //       id: '362bd43d7da0a0e4963fbde594b3b9ed'
    }
  //    ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //    signature: '0xf09eb344c7cbe4aebd7c3d2109eeddd5a3f1ec6a445a26ed1c46f47bce902a274af03b86f19557026055467a796a7e76be4c1fdd19132fd102097abe3124af081c',
  //    userAuthenticationToken: '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7',
  //   encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  const request = {
    username,
    recoveryCodeId: generateRecoveryCodeResponse.offlineRecoveryCode.id,
    ethereumAddress: encryptedWallet.ethereumAddress,
    signature: encryptedWallet.signature,
    userRecoveryCodeAuthenticationToken:
      encryptedWallet.userRecoveryCodeAuthenticationToken,
    encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
  };
  // look at server part below to see what your server is expected to do
  await fetch('YOUR_SERVER_API_SAVE_RECOVERY_OFFLINE_CODE_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  // generate offline recovery code is done!
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
  serverHashMatchesClientHash,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface EncryptedInfoRequest {
  username: string;
  userAuthenticationToken: string;
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const encryptedInfo = async (
  encryptedInfoRequest: EncryptedInfoRequest
) => {
  const encryptedInfo = await db.userAuthenticationInfo(
    encryptedInfoRequest.username
  );
  if (!encryptedInfo) {
    throw new Error('User does not exists');
  }

  const serverHashMatchesClientHash = await serverHashMatchesClientHash(
    encryptedInfo.salt,
    encryptedInfoRequest.userAuthenticationToken,
    encryptedInfo.serverAuthenticationHash
  );
  if (!serverHashMatchesClientHash) {
    throw new Error(
      '401 > this does not match the user auth token (wrong username + password).'
    );
  }

  return {
    encryptedKeyInfo: {
      key: userAuthenticationInfo.encryptedPk,
      iv: userAuthenticationInfo.encryptedPkIv,
    },
  };
};

interface OfflineRecoveryCodeRequest {
  username: string;
  recoveryCodeId: string;
  ethereumAddress: string;
  signature: string;
  userRecoveryCodeAuthenticationToken: string;
  encryptedKeyInfo: {
    key: string;
    iv: string;
  };
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const saveGeneratedOfflineRecoveryCode = async (
  offlineRecoveryCodeRequest: OfflineRecoveryCodeRequest
) => {
  const userExists = await db.userExists(offlineRecoveryCodeRequest.username);
  if (!userExists) {
    throw new Error('Username does not exists');
  }

  const recoveryCodeExists = await db.recoveryCodeExists(
    offlineRecoveryCodeRequest.recoveryCodeId
  );
  if (recoveryCodeExists) {
    throw new Error('Recovery code id already exists');
  }

  const ownsEthereumAddress = await verifyEthereumAddress(
    offlineRecoveryCodeRequest.signature,
    offlineRecoveryCodeRequest.encryptedKeyInfo,
    offlineRecoveryCodeRequest.ethereumAddress
  );
  if (!ownsEthereumAddress) {
    throw new Error(
      'You do not own the ethereum address so can not register you'
    );
  }

  const serverAuthHashResult = await hashAuthenticationTokenOnServer(
    offlineRecoveryCodeRequest.userRecoveryCodeAuthenticationToken
  );
  console.log(serverAuthHashResult);
  // {
  //    salt: '0x2e7199cd889426be35d730aabc3fa073',
  //    serverAuthenticationHash: '0xf06e83e0086d2546cc7730eeee08bc739daa2af80fb34691ebc0a0964b96eb34',
  //}

  await db.saveOfflineRecoveryCode({
    username: changeUsernameInfo.username,
    recoveryCodeId: offlineRecoveryCodeRequest.recoveryCodeId,
    serverAuthenticationHash: serverAuthHashResult.serverAuthenticationHash,
    salt: serverAuthHashResult.salt,
    encryptedPk: offlineRecoveryCodeRequest.encryptedKeyInfo.key,
    encryptedPkIv: offlineRecoveryCodeRequest.encryptedKeyInfo.iv,
  });

  // done - user has saved the offline recovery code!
};
```

#### Recover using offline codes

If the user wants to recover remember you got their recovery encrypted data on the server.

##### Flow

![recover with offline code flow](sequences/6.recover-with-offline-code.svg)

##### Client

```ts
import {
  getOfflineRecoveryAuthenticationInfo,
  recoverWithOfflineCode,
} from 'ethereum-web2-encryption';

// They have just submitted the recover by entered their username and offline recovery code
// on the UI
export const getRecoveryEncryptedInformation = async (
  username: string,
  offlineRecoveryId: string
) => {
  const recoveryAuthenticationInfo = await getOfflineRecoveryAuthenticationInfo(
    username,
    password
  );

  const request = {
    username,
    recoveryAuthenticationToken:
      recoveryAuthenticationInfo.recoveryAuthenticationToken,
    offlineRecoveryCodeId: recoveryAuthenticationInfo.recoveryId,
  };

  // look at server part below to see what your server is expected to do
  const response = await fetch(
    'YOUR_SERVER_API_GET_RECOVERY_ENCRYPTED_INFO_ENDPOINT',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    }
  );

  const recoveryEncryptedKeyInfo = await response.json();
  console.log(recoveryEncryptedKeyInfo);
  // {
  //   recoveryEncryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  // the user now needs to enter their new password, you should hold the
  // the encryptedKeyInfo somewhere ready for the next method below
  // below method should show you what the next steps are
};

interface RecoverWithOfflineRecoveryCodeRequest {
  username: string;
  recoveryCode: string;
  newPassword: string;
  encryptedKeyInfo: { key: string; iv: string };
}

// They have just clicked change email entered their new password and pressed enter
export const recoverWithOfflineCode = async (
  offlineRecoveryRequest: RecoverWithOfflineRecoveryCodeRequest
) => {
  const authenticationToken = await getAuthenticationToken(
    offlineRecoveryRequest.username,
    offlineRecoveryRequest.newPassword
  );

  const recoverWithOfflineCodeResponse = await recoverWithOfflineCode(
    offlineRecoveryRequest.username,
    offlineRecoveryRequest.recoveryCode,
    offlineRecoveryRequest.newPassword,
    offlineRecoveryRequest.encryptedKeyInfo
  );
  console.log(recoverWithOfflineCodeResponse);
  // {
  //    offlineRecoveryId: '362bd43d7da0a0e4963fbde594b3b9ed',
  //    wallet: {
  //        ethereumAddress: '0xa31e0D672AA9c6c4Ce863Bd17d1c7c9d6C56D5E8',
  //        privateKey: '0x602cbc76611ae50bcff99beacb4ab8e84853830f3036da946a8473107c4056e8',
  //    },
  //    signature: '0xf09eb344c7cbe4aebd7c3d2109eeddd5a3f1ec6a445a26ed1c46f47bce902a274af03b86f19557026055467a796a7e76be4c1fdd19132fd102097abe3124af081c',
  //    userAuthenticationToken: '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7',
  //    encryptedKeyInfo: {
  //       key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
  //       iv: '0xa3b054976a6ffc7fa1c527577480b663',
  //    }
  //}

  const request = {
    username,
    recoveryCodeId: recoverWithOfflineCodeResponse.offlineRecoveryId,
    ethereumAddress: recoverWithOfflineCodeResponse.ethereumAddress,
    signature: recoverWithOfflineCodeResponse.signature,
    userRecoveryCodeAuthenticationToken:
      recoverWithOfflineCodeResponse.userRecoveryCodeAuthenticationToken,
    encryptedKeyInfo: recoverWithOfflineCodeResponse.encryptedKeyInfo,
  };
  // look at server part below to see what your server is expected to do
  await fetch('YOUR_SERVER_API_REDEEM_RECOVERY_OFFLINE_CODE_ENDPOINT', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  // redeemed offline recovery code! user has now been authenticated and can use their new wallet.
};
```

##### Server

```ts
import {
  verifyEthereumAddress,
  hashAuthenticationTokenOnServer,
  serverHashMatchesClientHash,
} from 'ethereum-web2-encryption';
import db from 'YOUR_DB';

interface RecoveryEncryptedInfoRequest {
  username: string;
  recoveryAuthenticationToken: string;
  offlineRecoveryCodeId: string;
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const recoveryEncryptedInfo = async (
  recoveryEncryptedInfoRequest: RecoveryEncryptedInfoRequest
) => {
  const encryptedInfo = await db.userRecoveryEncryptedInfo(
    recoveryEncryptedInfoRequest.username,
    recoveryEncryptedInfoRequest.offlineRecoveryCodeId
  );
  if (!encryptedInfo) {
    throw new Error(
      'Offline recovery code has been redeemed or does not exists'
    );
  }

  const serverHashMatchesClientHash = await serverHashMatchesClientHash(
    encryptedInfo.salt,
    recoveryEncryptedInfoRequest.recoveryAuthenticationToken,
    encryptedInfo.serverAuthenticationHash
  );
  if (!serverHashMatchesClientHash) {
    throw new Error(
      '401 > this does not match the recovery auth token (wrong username + recoveryCode).'
    );
  }

  return {
    recoveryEncryptedKeyInfo: {
      key: encryptedInfo.encryptedPk,
      iv: encryptedInfo.encryptedPkIv,
    },
  };
};

interface RedeemOfflineRecoveryCodeRequest {
  username: string;
  offlineRecoveryCodeId: string;
  ethereumAddress: string;
  signature: string;
  userRecoveryCodeAuthenticationToken: string;
  encryptedKeyInfo: {
    key: string;
    iv: string;
  };
}

// They client has called the server endpoint which then calls this
// will keep in 1 method so its easy to follow
export const redeemOfflineRecoveryCode = async (
  redeemOfflineRecoveryCodeRequest: RedeemOfflineRecoveryCodeRequest
) => {
  const userExists = await db.userExists(
    redeemOfflineRecoveryCodeRequest.username
  );
  if (!userExists) {
    throw new Error('Username does not exists');
  }

  const recoveryCodeExists = await db.recoveryCodeExists(
    redeemOfflineRecoveryCodeRequest.offlineRecoveryCodeId
  );
  if (!recoveryCodeExists) {
    throw new Error('Recovery code id does not exist');
  }

  const ownsEthereumAddress = await verifyEthereumAddress(
    redeemOfflineRecoveryCodeRequest.signature,
    redeemOfflineRecoveryCodeRequest.encryptedKeyInfo,
    redeemOfflineRecoveryCodeRequest.ethereumAddress
  );
  if (!ownsEthereumAddress) {
    throw new Error('You do not own the ethereum address so can not recover');
  }

  const serverAuthHashResult = await hashAuthenticationTokenOnServer(
    redeemOfflineRecoveryCodeRequest.userRecoveryCodeAuthenticationToken
  );
  console.log(serverAuthHashResult);
  // {
  //    salt: '0x2e7199cd889426be35d730aabc3fa073',
  //    serverAuthenticationHash: '0xf06e83e0086d2546cc7730eeee08bc739daa2af80fb34691ebc0a0964b96eb34',
  //}

  await db.updateUserEncryptedData({
    username: changeUsernameInfo.username,
    serverAuthenticationHash: serverAuthHashResult.serverAuthenticationHash,
    salt: serverAuthHashResult.salt,
    encryptedPk: offlineRecoveryCodeRequest.encryptedKeyInfo.key,
    encryptedPkIv: offlineRecoveryCodeRequest.encryptedKeyInfo.iv,
  });

  await db.redeemedOfflineRecoveryCode({
    username: changeUsernameInfo.username,
    recoveryCodeId: offlineRecoveryCodeRequest.offlineRecoveryCodeId,
  });

  // done - user has now redeemed and changed their password!
};
```

## Explaining server node calls

If you are not using node for your backend then you can not use the exposed methods in the flow diagram. This will explain what the methods do so you can write them in your backend language of choice.

### hashAuthenticationTokenOnServer

This method hashes the client authentication token with a random salt to create you a server authentication token for that user. The built in method returns a `salt` and a `serverAuthenticationHash`

- salt = random generated 16 bytes
- serverAuthenticationHash = PBKDF(password: client_authentication_token, salt: randomBytes(16), iterations: 100000) then turned into a hex string

### serverHashMatchesClientHash

This method compares the passed in client authentication token to the server authentication hash to make sure the token is valid for that user. The build in method returns a boolean.

Parameters:

- userStoredSalt = The stored salt which was used to do the `hashAuthenticationTokenOnServer`
- clientAuthenticationToken = The client authentication that the client passed to the server
- serverAuthenticationHash = The server authentication hash that was generated by the `hashAuthenticationTokenOnServer`

algo = serverAuthenticationHash === PBKDF(password: client_authentication_token, salt: userStoredSalt, iterations: 100000)

### verifyEthereumAddress

This method uses the `ecdsaRecover` logic which most languages have ways to support this so I will not explain how it works.

## How does the encryption work and how is it safe

- Break down keys and why they are safe etc etc!! explain in proper algo terms.
