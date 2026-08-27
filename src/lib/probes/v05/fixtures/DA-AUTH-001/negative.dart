import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

String mint(Map<String, dynamic> claims, String secret) {
  final jwt = JWT(claims);
  return jwt.sign(SecretKey(secret), expiresIn: Duration(minutes: 15));
}
