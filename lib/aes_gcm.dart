import 'dart:typed_data';

import 'package:pc_steelcrypt/pointycastle.dart';

class AesGcm {
  Uint8List _key32;

  AesGcm(this._key32);

  String encrypt(String input, [Uint8List iv]) {
    CipherParameters params = PaddedBlockCipherParameters(
        ParametersWithIV<KeyParameter>(KeyParameter(_key32), iv), null);
    PaddedBlockCipher cipher = PaddedBlockCipher('AES/GCM/PKCS7');
    cipher..init(true, params);
    Uint8List inter = cipher.process(Uint8List.fromList(input.codeUnits));
    return String.fromCharCodes(inter);
  }

  String decrypt(String encrypted, [Uint8List iv]) {
    CipherParameters params = PaddedBlockCipherParameters(
        ParametersWithIV(KeyParameter(_key32), iv), null);
    PaddedBlockCipher cipher = PaddedBlockCipher('AES/GCM/PKCS7');
    cipher..init(false, params);
    Uint8List inter = cipher.process(Uint8List.fromList(encrypted.codeUnits));
    return String.fromCharCodes(inter);
  }
}
