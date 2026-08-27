import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

Map<String, dynamic> readToken(String token, String secret) {
  final jwt = JWT.verify(token, SecretKey(secret), checkExpiresIn: false);
  return jwt.payload;
}
