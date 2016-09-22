var forge = require('node-forge');

var defaultAttrs = [
  { name: 'countryName', value: 'AT' },
  { name: 'organizationName', value: 'DigitalSunray' },
  { shortName: 'ST', value: 'Vienna' },
  { shortName: 'OU', value: 'DigitalSunray SSL Proxy'}
];

function getKeysAndCert(serialNumber){
  var keys = forge.pki.rsa.generateKeyPair(2048);
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber || (Math.floor(Math.random() * 100000) + '');
  cert.validity.notBefore = new Date();
  cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1); // yesterday
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getHours() + 24); // 1 day
  return {
    keys: keys,
    cert: cert
  };
}

function generateRootCA(){
  if(!username)
    throw new Error("username is undefined");
  var keysAndCert = getKeysAndCert();
  keys = keysAndCert.keys;
  cert = keysAndCert.cert;

  var attrsIssuer = defaultAttrs.concat([
    {
      name: 'commonName',
      value: 'DSR'
    }
  ]);
  var attrsSubj = defaultAttrs.concat([
    {
      name: 'commonName',
      value: 'DSR'
    }
  ]);
  cert.setSubject(attrsSubj);
  cert.setIssuer(attrsIssuer);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    // { name: 'keyUsage', keyCertSign: true, digitalSignature: true, nonRepudiation: true, keyEncipherment: true, dataEncipherment: true },
    // { name: 'extKeyUsage', serverAuth: true, clientAuth: true, codeSigning: true, emailProtection: true, timeStamping: true },
    // { name: 'nsCertType', client: true, server: true, email: true, objsign: true, sslCA: true, emailCA: true, objCA: true },
    // { name: 'subjectAltName', altNames: [ { type: 6, /* URI */ value: 'http://example.org/webid#me' }, { type: 7, /* IP */ ip: '127.0.0.1' } ] },
    // { name: 'subjectKeyIdentifier' }
  ]);

  cert.sign(keys.privateKey, forge.md.sha512.create());

  return {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert)
  };

  return pem;
}

function generateCertsForHostname(domain, rootCAConfig){

  //generate a serialNumber for domain
  var md = forge.md.md5.create();
  md.update(domain);

  var keysAndCert = getKeysAndCert(md.digest().toHex());
  keys = keysAndCert.keys;
  cert = keysAndCert.cert;

  var caCert    = forge.pki.certificateFromPem(rootCAConfig.cert);
  var caKey     = forge.pki.privateKeyFromPem(rootCAConfig.key);

  // issuer from CA
  cert.setIssuer(caCert.subject.attributes);

  var attrs = defaultAttrs.concat([
    {
      name: 'commonName',
      value: domain
    }
  ]);
  cert.setSubject(attrs);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert)
  };
}

module.exports.generateRootCA = generateRootCA;
module.exports.generateCertsForHostname = generateCertsForHostname;
