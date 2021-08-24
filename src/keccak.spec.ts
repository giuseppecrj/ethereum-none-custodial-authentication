import { keccak } from './keccak';

describe('keccak', () => {
  it('should hash the uint8array', () => {
    expect(
      keccak(
        new Uint8Array([
          28, 209, 85, 192, 92, 147, 183, 53, 106, 71, 158, 215, 29, 214, 182,
          124,
        ])
      )
    ).toEqual(
      '0xc42e1fcd8db1d7024f00ed854c487ba74634fb0e508bc96b009d54761d7a6d68'
    );
  });
});
