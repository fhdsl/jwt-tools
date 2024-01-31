  function createToken(userid,kid,secret,iss,scp){
    var header = {
      "alg": "HS256",
      "typ": "JWT",
      "iss": iss,
      "kid": kid,
    };
    var stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header));
    var encodedHeader = base64url(stringifiedHeader);
    var claimSet = {
      "sub": userid,
      "aud":"tableau",
      "nbf":Math.round(new Date().getTime()/1000)-100,
      "jti":new Date().getTime().toString(),
      "iss": iss,
      "scp": scp,
      "exp": Math.round(new Date().getTime()/1000)+100
    };
    var stringifiedData = CryptoJS.enc.Utf8.parse(JSON.stringify(claimSet));
    var encodedData = base64url(stringifiedData);
    var token = encodedHeader + "." + encodedData;
    var signature = CryptoJS.HmacSHA256(token, secret);
    signature = base64url(signature);
    var signedToken = token + "." + signature;
    return signedToken;
  }
  
  function base64url(source) {
    encodedSource = CryptoJS.enc.Base64.stringify(source);
    encodedSource = encodedSource.replace(/=+$/, '');
    encodedSource = encodedSource.replace(/\+/g, '-');
    encodedSource = encodedSource.replace(/\//g, '_');
    return encodedSource;
  }
