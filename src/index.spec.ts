import {
  changePassword,
  changeUsername,
  createWallet,
  decryptWallet,
  EncryptedKeyInfo,
  generateOfflineRecoveryCode,
  getAuthenticationToken,
  getRecoveryAuthenticationToken,
  recoverWithOfflineCode,
  verifyEthereumAddress,
} from './index';

describe('main functions', () => {
  it('should create an authentication token', async () => {
    const token = await getAuthenticationToken(
      'hello_world',
      'some_foo-boo_82738273'
    );
    expect(token).toEqual(
      '0xace36d94ae1397b87135d363f207a440c5b30a0f2ce2ebf181b6ded0df9c84e7'
    );
  });

  it('createWallet + descryptWallet + getAuthenticationToken round trip', async () => {
    const username = 'ether.eth';
    const password = 'eTHeReUm_ha4d_pa55W0Rd';
    const encryptedWallet = await createWallet(username, password);

    const authToken = await getAuthenticationToken(username, password);
    expect(authToken).toEqual(encryptedWallet.userAuthenticationToken);

    expect(encryptedWallet.signature).not.toBeUndefined();
    expect(
      verifyEthereumAddress(
        encryptedWallet.signature,
        encryptedWallet.encryptedKeyInfo,
        encryptedWallet.wallet.ethereumAddress
      )
    ).toEqual(true);

    const decryptedWallet = await decryptWallet(
      username,
      password,
      encryptedWallet.encryptedKeyInfo
    );

    expect(decryptedWallet.ethereumAddress).toEqual(
      encryptedWallet.wallet.ethereumAddress
    );
    expect(decryptedWallet.privateKey).not.toBeUndefined();
  });

  it('should decrypt wallet', async () => {
    const username = 'ether2.eth';
    const password = 'eTHeReUm_ha4d_pa55W0Rd222';
    const decryptedWallet = await decryptWallet(username, password, {
      key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
      iv: '0xa3b054976a6ffc7fa1c527577480b663',
    });

    expect(decryptedWallet.privateKey).toEqual(
      '0xcbe4e639a4bec6c285b23e37ce3a8ec4c0b2f4962f17fc4c3292e606a1aecc52'
    );

    expect(decryptedWallet.ethereumAddress).toEqual(
      '0xbD89Be78eb4280BAaa0fd8C0426159E893bd133d'
    );
  });

  it('changePassword', async () => {
    const username = 'ether2.eth';
    const password = 'eTHeReUm_ha4d_pa55W0Rd222';
    const changePasswordResult = await changePassword(
      username,
      { oldPassword: password, newPassword: '____233dnwdhDHd' },
      {
        key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
        iv: '0xa3b054976a6ffc7fa1c527577480b663',
      }
    );

    expect(changePasswordResult.wallet.privateKey).toEqual(
      '0xcbe4e639a4bec6c285b23e37ce3a8ec4c0b2f4962f17fc4c3292e606a1aecc52'
    );

    expect(changePasswordResult.wallet.ethereumAddress).toEqual(
      '0xbD89Be78eb4280BAaa0fd8C0426159E893bd133d'
    );

    expect(changePasswordResult.signature).not.toBeUndefined();
    expect(
      verifyEthereumAddress(
        changePasswordResult.signature,
        changePasswordResult.encryptedKeyInfo,
        changePasswordResult.wallet.ethereumAddress
      )
    ).toEqual(true);
  });

  it('changeUsername', async () => {
    const username = 'ether2.eth';
    const password = 'eTHeReUm_ha4d_pa55W0Rd222';
    const changeUsernameResult = await changeUsername(
      { newUsername: 'ether5.eth', oldUsername: username },
      password,
      {
        key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
        iv: '0xa3b054976a6ffc7fa1c527577480b663',
      }
    );

    expect(changeUsernameResult.wallet.privateKey).toEqual(
      '0xcbe4e639a4bec6c285b23e37ce3a8ec4c0b2f4962f17fc4c3292e606a1aecc52'
    );

    expect(changeUsernameResult.wallet.ethereumAddress).toEqual(
      '0xbD89Be78eb4280BAaa0fd8C0426159E893bd133d'
    );

    expect(changeUsernameResult.signature).not.toBeUndefined();
    expect(
      verifyEthereumAddress(
        changeUsernameResult.signature,
        changeUsernameResult.encryptedKeyInfo,
        changeUsernameResult.wallet.ethereumAddress
      )
    ).toEqual(true);
  });

  it('generateOfflineRecoveryCode + recoverWithOfflineCode + getRecoveryAuthenticationToken round trip', async () => {
    const username = 'ether2.eth';
    const password = 'eTHeReUm_ha4d_pa55W0Rd222';
    const encryptedKeyInfo: EncryptedKeyInfo = {
      key: '0xd0286e5b69d6003022a523e26bff0cdb1c2f28579ab692b10c0e68a7d3bb4b9a',
      iv: '0xa3b054976a6ffc7fa1c527577480b663',
    };
    const generateRecoveryCodeResponse = await generateOfflineRecoveryCode(
      username,
      password,
      encryptedKeyInfo
    );

    const authToken = await getRecoveryAuthenticationToken(
      username,
      generateRecoveryCodeResponse.offlineRecoveryCode
    );
    expect(authToken).toEqual(
      generateRecoveryCodeResponse.userRecoveryCodeAuthenticationToken
    );

    const recoveryResult = await recoverWithOfflineCode(
      username,
      generateRecoveryCodeResponse.offlineRecoveryCode,
      password,
      generateRecoveryCodeResponse.encryptedKeyInfo
    );

    expect(recoveryResult.wallet.ethereumAddress).toEqual(
      '0xbD89Be78eb4280BAaa0fd8C0426159E893bd133d'
    );
    expect(recoveryResult.wallet.privateKey).toEqual(
      '0xcbe4e639a4bec6c285b23e37ce3a8ec4c0b2f4962f17fc4c3292e606a1aecc52'
    );

    expect(recoveryResult.signature).not.toBeUndefined();
    expect(
      verifyEthereumAddress(
        recoveryResult.signature,
        recoveryResult.encryptedKeyInfo,
        recoveryResult.wallet.ethereumAddress
      )
    ).toEqual(true);
  });
});
