import { toHex } from './helpers';
import { generate } from './pbkdf';

describe('pbkdf', () => {
  it('should create pbkdf key', async () => {
    const key = await generate(
      'a_user_name',
      'a_password_should_be_stronger_then_this'
    );
    expect(toHex(key)).toEqual(
      '0x66e6e260c50f44d0a16465c59986f006330f75270f562ccf6ca6ad8cb921ea34'
    );
  });

  it('should create pbkdf key', async () => {
    const key = await generate(
      'joshstevenswashere@hotmail.com',
      'h09hqzOCkH5L9BrLCzawTdsJh0jaXbbsr2bD2RRUy2i77jIUwEzm6SIbcDnhUOZWl61TjcXV4pirsD6dESTyH7ccSnkcdyg5wtg'
    );
    expect(toHex(key)).toEqual(
      '0xc8439585d68013b8469c61a2a6580b4788becc6f873de5f277dbd10b3e57a19b'
    );
  });
});
