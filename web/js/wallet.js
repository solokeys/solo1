DEVELOPMENT = 0;

var to_b58 = function(B){var A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";var d=[],s="",i,j,c,n;for(i in B){j=0,c=B[i];s+=c||s.length^i?"":1;while(j in d||c){n=d[j];n=n?n*256+c:c;c=n/58|0;d[j]=n%58;j++}}while(j--)s+=A[d[j]];return s};
var from_b58 = function(S){var A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";var d=[],b=[],i,j,c,n;for(i in S){j=0,c=A.indexOf(S[i]);if(c<0)throw new Error('Invald b58 character');c||b.length^i?i:b.push(0);while(j in d||c){n=d[j];n=n?n*58+c:c;c=n>>8;d[j]=n%256;j++}}while(j--)b.push(d[j]);return new Uint8Array(b)};

// Calculate the Shannon entropy of a string in bits per symbol.
// https://gist.github.com/jabney/5018b4adc9b2bf488696
(function(shannon) {
    'use strict';

    // Create a dictionary of character frequencies and iterate over it.
    function process(s, evaluator) {
        var h = Object.create(null), k;
        s.split('').forEach(function(c) {
            h[c] && h[c]++ || (h[c] = 1); });
        if (evaluator) for (k in h) evaluator(k, h[k]);
        return h;
    };

    // Measure the entropy of a string in bits per symbol.
    shannon.entropy = function(s) {
        var sum = 0,len = s.length;
        process(s, function(k, f) {
            var p = f/len;
            sum -= p * Math.log(p) / Math.log(2);
        });
        return sum;
    };

    // Measure the entropy of a string in total bits.
    shannon.bits = function(s) {
        return shannon.entropy(s) * s.length;
    };

    // Log the entropy of a string to the console.
    shannon.log = function(s) {
        console.log('Entropy of "' + s + '" in bits per symbol:', shannon.entropy(s));
    };
})(window.shannon = window.shannon || Object.create(null));

function hex(byteArray, join) {
  if (join === undefined) join = ' ';
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join(join)
}

// Convert from normal to web-safe, strip trailing "="s
function webSafe64(base64) {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Convert from web-safe to normal, add trailing "="s
function normal64(base64) {
    return base64.replace(/\-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3*base64.length)%4);
}

function websafe2array(base64) {
    var binary_string =  window.atob(normal64(base64));
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

function array2websafe(array) {
    var result = "";
    for(var i = 0; i < array.length; ++i){
        result+= (String.fromCharCode(array[i]));
    }
    return webSafe64(window.btoa(result));
}

function string2websafe(string) {
    return webSafe64(window.btoa(string));
}
function websafe2string(string) {
    return window.atob(normal64(string));
}
function string2array(string) {

    var bytes = new Uint8Array( string.length );

    for (var i = 0; i < string.len; i++) {
        bytes[i] = string.charCodeAt(i);
    }

    return bytes;
}
function hex2array(string)
{
    if (string.slice(0,2) == '0x')
    {
        string = string.slice(2,string.length);
    }
    if (string.length & 1)
    {
        throw new Error('Odd length hex string');
    }
    var arr = new Uint8Array(string.length/2);
    var i;
    for (i = 0; i < string.length; i+=2)
    {
        arr[i/2] = parseInt(string.slice(i,i+2),16);
    }
    return arr;
}


// @key input private key in hex string format
function key2wif(key)
{
    //2
    key = '0x80' + key;

    bin = hex2array(key);

    //3
    var hash = sha256.create();
    hash.update(bin);
    bin = hash.array();

    //4
    hash = sha256.create();
    hash.update(bin);
    bin = hash.array();

    // 5
    var chksum = bin.slice(0,4);

    // 6
    key = key + array2hex(chksum);

    // 7
    key = hex2array(key);
    key = to_b58(key);

    return key;
}



function array2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// https://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array
function toUTF8Array(str) {
    var utf8 = [];
    for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                      0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >>18),
                      0x80 | ((charcode>>12) & 0x3f),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
    }
    return utf8;
}
function error2string(err)
{
    var lut = {     // Only some of these are used
        0x00 : 'CTAP1_SUCCESS',
        0x01 : 'CTAP1_ERR_INVALID_COMMAND',
        0x02 : 'CTAP1_ERR_INVALID_PARAMETER',
        0x03 : 'CTAP1_ERR_INVALID_LENGTH',
        0x04 : 'CTAP1_ERR_INVALID_SEQ',
        0x05 : 'CTAP1_ERR_TIMEOUT',
        0x06 : 'CTAP1_ERR_CHANNEL_BUSY',
        0x0A : 'CTAP1_ERR_LOCK_REQUIRED',
        0x0B : 'CTAP1_ERR_INVALID_CHANNEL',
        0x10 : 'CTAP2_ERR_CBOR_PARSING',
        0x11 : 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
        0x12 : 'CTAP2_ERR_INVALID_CBOR',
        0x13 : 'CTAP2_ERR_INVALID_CBOR_TYPE',
        0x14 : 'CTAP2_ERR_MISSING_PARAMETER',
        0x15 : 'CTAP2_ERR_LIMIT_EXCEEDED',
        0x16 : 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
        0x17 : 'CTAP2_ERR_TOO_MANY_ELEMENTS',
        0x18 : 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED',
        0x19 : 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
        0x20 : 'CTAP2_ERR_CREDENTIAL_NOT_VALID',
        0x21 : 'CTAP2_ERR_PROCESSING',
        0x22 : 'CTAP2_ERR_INVALID_CREDENTIAL',
        0x23 : 'CTAP2_ERR_USER_ACTION_PENDING',
        0x24 : 'CTAP2_ERR_OPERATION_PENDING',
        0x25 : 'CTAP2_ERR_NO_OPERATIONS',
        0x26 : 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
        0x27 : 'CTAP2_ERR_OPERATION_DENIED',
        0x28 : 'CTAP2_ERR_KEY_STORE_FULL',
        0x29 : 'CTAP2_ERR_NOT_BUSY',
        0x2A : 'CTAP2_ERR_NO_OPERATION_PENDING',
        0x2B : 'CTAP2_ERR_UNSUPPORTED_OPTION',
        0x2C : 'CTAP2_ERR_INVALID_OPTION',
        0x2D : 'CTAP2_ERR_KEEPALIVE_CANCEL',
        0x2E : 'CTAP2_ERR_NO_CREDENTIALS',
        0x2F : 'CTAP2_ERR_USER_ACTION_TIMEOUT',
        0x30 : 'CTAP2_ERR_NOT_ALLOWED',
        0x31 : 'CTAP2_ERR_PIN_INVALID',
        0x32 : 'CTAP2_ERR_PIN_BLOCKED',
        0x33 : 'CTAP2_ERR_PIN_AUTH_INVALID',
        0x34 : 'CTAP2_ERR_PIN_AUTH_BLOCKED',
        0x35 : 'CTAP2_ERR_PIN_NOT_SET',
        0x36 : 'CTAP2_ERR_PIN_REQUIRED',
        0x37 : 'CTAP2_ERR_PIN_POLICY_VIOLATION',
        0x38 : 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
        0x39 : 'CTAP2_ERR_REQUEST_TOO_LARGE',
    }
    return lut[err]
}

var CMD = {
    sign: 0x10,
    register: 0x11,
    pin: 0x12,
    reset: 0x13,
    version: 0x14,
    rng: 0x15,
    pubkey: 0x16,
    boot_write: 0x40,
    boot_done: 0x41,
    boot_check: 0x42,
    boot_erase: 0x43,
    boot_version: 0x44,
};

var PIN = {
    getRetries: 0x01,
    getKeyAgreement: 0x02,
    setPin: 0x03,
    changePin: 0x04,
    getPinToken: 0x05,
};

// Create XHR object.
function createCORSRequest(method, url) {
    var xhr = new XMLHttpRequest();
    if ("withCredentials" in xhr) {
        // XHR for Chrome/Firefox/Opera/Safari.
        xhr.open(method, url, true);
    } else if (typeof XDomainRequest != "undefined") {
        // XDomainRequest for IE.
        xhr = new XDomainRequest();
        xhr.open(method, url);
    } else {
        // CORS not supported.
        xhr = null;
    }
    return xhr;
}

function parse_device_response(arr)
{
    var dataview = new DataView(arr.slice(1,5).buffer);

    count = dataview.getUint32(0,true); // get count as 32 bit LE integer

    data = null;
    if (arr[5] == 0) {
        data = arr.slice(6,arr.length);

    }
    return {count: count, status: error2string(arr[5]), data: data};
}



// For development purposes
function send_msg_http(data, func, timeout) {
    var url = 'https://localhost:8080';

    var req = JSON.stringify({data: array2websafe(data)});

    var xhr = createCORSRequest('POST', url);

    if (!xhr) {
        console.log('CORS not supported');
        return;
    }

    // Response handlers.
    xhr.onload = function() {
        var text = xhr.responseText;
        var resp = JSON.parse(text);
        arr = websafe2array(resp.data);
        data = parse_device_response(arr);
        if (func) func(data);
    };

    xhr.onerror = function() {
        console.log('Woops, there was an error making the request.');
    };

    xhr.send(req);
}

function get_firmware_http_(func) {
    var url = 'https://localhost:8080';

    var xhr = createCORSRequest('GET', url);

    if (!xhr) {
        console.log('CORS not supported');
        return;
    }

    // Response handlers.
    xhr.onload = function() {
        var text = xhr.responseText;
        var resp = JSON.parse(text);
        resp.firmware = websafe2string(resp.firmware);
        if (func) func(resp);
    };

    xhr.onerror = function() {
        console.log('Woops, there was an error making the request.');
    };

    xhr.send();
}

// For real
function send_msg_u2f(data, func, timeout) {
    // Use key handle and signature response as comm channel
    var d = new Date();
    var t1 = d.getTime();
    timeout = timeout || 5;

    var appid = window.location.origin;
    //var chal = string2websafe('AABBCC');

    var chal = array2websafe(hex2array('d1cd7357bcedc03fcec112fe5a7f3f890292ff6f758978928b736ce1e63479e5'));

    var args = {
        type: 'navigator.id.getAssertion',
        challenge: chal,
        origin: appid
    };

    var keyHandle = array2websafe(data);

    var key = {
        version: 'U2F_V2',
        keyHandle: keyHandle,
        transports: [],
        appId: appid
    };

    window.u2f.sign(appid,chal,[key], function(res){
        var d2 = new Date();
        t2 = d2.getTime();
        if (!res.signatureData)
            func(res);
        sig = websafe2array(res.signatureData)
        data = parse_device_response(sig);
        func(data);

    },timeout);
}

var send_msg;
if (DEVELOPMENT) {
    send_msg = send_msg_http;
} else {
    send_msg = send_msg_u2f;
}

function formatBootRequest(cmd, addr, data) {
    var array = new Uint8Array(255);

    data = data || new Uint8Array(1);

    if (data.length > (255 - 9)) {
        throw new Error("Max size exceeded");
    }

    array[0] = cmd & 0xff;
    array[1] = (addr >> 0) & 0xff;
    array[2] = (addr >> 8) & 0xff;
    array[3] = (addr >> 16) & 0xff;

    array[4] = 0x8C;    // Wallet tag.  To not interfere with U2F devices.
    array[5] = 0x27;
    array[6] = 0x90;
    array[7] = 0xf6;

    array[8] = 0;
    array[9] = data.length & 0xff;

    var offset = 10;

    var i;
    for (i = 0; i < data.length; i++){
        array[offset + i] = data[i];
    }
    return array;
}

// Format a request message
// @cmd 0-255 value command
// @p1,p2 optional "sub" commands/arguments, each 0-255 valued.
// @pinAuth 16 byte Uint8Array needed for most commands to authorize command
// @args array of Uint8Arrays, arguments for the command being run
function formatRequest(cmd, p1, p2, pinAuth, args) {
    var argslen = 0;
    var i,j;
    args = args || [];
    for (i = 0; i < args.length; i+=1) {
        argslen += args[i].length + 1
    }
    var len = 16 + 4 + 4 +argslen;

    if (len > 255)
    {
        throw new Error('Total length of request cannot exceed 255 bytes');
    }

    var array = new Uint8Array(len);

    array[0] = cmd & 0xff;
    array[1] = p1 & 0xff;
    array[2] = p2 & 0xff;
    array[3] = (args.length) & 0xff;

    array[4] = 0x8C;    // Wallet tag.  To not interfere with U2F devices.
    array[5] = 0x27;
    array[6] = 0x90;
    array[7] = 0xf6;

    var offset = 8;

    if (pinAuth) {
        for (i = 0; i < 16; i += 1) {
            array[offset + i] = pinAuth[i];
        }
    }

    offset = offset + i;

    for (i = 0; i < args.length; i += 1) {
        array[offset] = args[i].length;
        offset += 1
        for (j = 0; j < args[i].length; j += 1) {
            array[offset] = args[i][j];
            offset += 1
        }
    }
    return array;
}

// Computes sha256 HMAC
// @pinToken is key for HMAC
// @cmd,p1,p2 each are bytes input to HMAC
// @args array of Uint8Arrays input to HMAC
// @return first 16 bytes of HMAC
function computePinAuth(pinToken, cmd,p1,p2,args)
{
    var hmac = sha256.hmac.create(pinToken);
    var i;
    hmac.update([cmd]);
    hmac.update([p1]);
    hmac.update([p2]);
    if (args && args.length) hmac.update([args.length]);
    else hmac.update([0]);

    hmac.update([0x8c,0x27,0x90,0xf6]);

    if (args) {
        for (i = 0; i < args.length; i++)
        {
            hmac.update([args[i].length]);
            hmac.update(args[i]);
        }
    }

    return hmac.array().slice(0,16)
}

function computePinAuthRaw(pinToken, data)
{
    var hmac = sha256.hmac.create(pinToken);
    hmac.update(data);
    return hmac.array().slice(0,16)
}

// @sigAlg is a number 0-255
// @pinAuth token, see pinToken information.  Uint8Array
// @challenge is websafe base64 string.  Data to be signed.
// @keyid is optional, websafe base64 string
function signRequestFormat(sigAlg,pinToken,challenge,keyid) {
// Sign request
// Field                Value               length
// op:                  0x10                1
// authType:            sigAlg              1
// reserved:            0x00                1
// pinHashEnc:          [dynamic]           16
// challenge-length:    challenge.length    1
// challenge:           challenge           1-234
// keyID-length:        keyid.length        1
// keyID:               keyid               0-233
// Note: total size must not exceed 255 bytes

    var cmd = CMD.sign;
    var p1 = sigAlg;
    var p2 = 0;

    if (typeof(challenge) == 'string')
    {
        challenge = websafe2array(challenge);
    }

    var args = [challenge];
    if (keyid) args.push(keyid)

    var pinAuth;

    if (pinToken) pinAuth = computePinAuth(pinToken,cmd,p1,p2,args);
    else pinAuth = new Uint8Array(16);

    var req = formatRequest(cmd,p1,p2,pinAuth,args);

    return req;
}

// @wifkey is wif key in base58 format string
function registerRequestFormat(wifkey, pinToken) {

    var cmd = CMD.register;
    var p1 = 0;
    var p2 = 0;
    var keyarr = from_b58(wifkey);
    var args = [keyarr];

    var pinAuth;

    if (pinToken) pinAuth = computePinAuth(pinToken,cmd,p1,p2,args);
    else pinAuth = new Uint8Array(16);

    var req = formatRequest(cmd,p1,p2,pinAuth,args);

    return req;
}

// @subCmd is one of the following in PIN {}
function pinRequestFormat(subcmd, pinAuth, pubkey, pinEnc, pinHashEnc) {

    var cmd = CMD.pin;
    var p1 = subcmd;
    var p2 = 0;
    //var args = [challenge];
    //if (keyid) args.push(keyid)
    pinAuth = pinAuth || new Uint8Array(16);
    var args = [];

    if (pubkey) args.push(pubkey);
    if (pinEnc) args.push(pinEnc);
    if (pinHashEnc) args.push(pinHashEnc);

    //var pinAuth = computePinAuth(pinToken,cmd,p1,p2,args);
    //console.log(hex(pinAuth));
    var req = formatRequest(cmd,p1,p2,pinAuth,args);

    return req;
}

var get_shared_secret_ = function(func) {
    // Get temporary pubkey from device to compute shared secret
    var req = pinRequestFormat(PIN.getKeyAgreement);
    var self = this;
    send_msg(req, function(resp){

        if (resp.status == 'CTAP1_SUCCESS') {
            var i;

            var devicePubkeyHex = '04'+hex(resp.data,'');
            var devicePubkey = self.ecp256.keyFromPublic(devicePubkeyHex,'hex');

            // Generate a new key pair for shared secret
            var platform_keypair = self.ecp256.genKeyPair();
            self.platform_keypair = platform_keypair;


            // shared secret
            var shared = platform_keypair.derive(devicePubkey.getPublic()).toArray();
            var hash = sha256.create();
            hash.update(shared);
            shared = hash.array();

            resp.data = shared;
        }
        if (func) func(resp);

    });
};

var authenticate_ = function(pin, func){
    if (! this.shared_secret){
        throw new Error('Device is not connected.');
    }
    hash = sha256.create();
    hash.update(toUTF8Array(pin));
    pinHash = hash.array().slice(0,16);

    var iv = new Uint8Array(16);
    iv.fill(0);

    var aesCbc = new aesjs.ModeOfOperation.cbc(this.shared_secret, iv);
    pinHashEnc = aesCbc.encrypt(pinHash);


    var ourPubkey = this.platform_keypair.getPublic(undefined, 'hex');
    var ourPubkeyBytes = hex2array(ourPubkey.slice(2,ourPubkey.length));


    var req = pinRequestFormat(PIN.getPinToken, pinHashEnc, ourPubkeyBytes);


    var self = this;

    send_msg(req, function(resp){
        var aesCbc = new aesjs.ModeOfOperation.cbc(self.shared_secret, iv);
        var pinTokenEnc = resp.data;
        if  (resp.status == 'CTAP1_SUCCESS') {
            var pinToken = aesCbc.decrypt(pinTokenEnc);
            self.pinToken = pinToken;
            if (func) func({pinToken: pinToken, status: resp.status});
        }   else {

            self.init(function(){
                if (func) func(resp);
            });
        }
    });
};

function pin2bytes(pin){
    var pinBytes = toUTF8Array(pin);

    var encLen = pinBytes.length + (16-(pinBytes.length % 16));

    if (encLen < 64){
        encLen = 64;
    }

    if (pin.length < 4){
        throw Error('FIDO2 pin must be at least 4 unicode characters.');
    }
    if (encLen > 255){
        throw Error('FIDO2 pin may not exceed 255 bytes');
    }
    if (encLen > 80){
        throw Error('Recommended to not use pins longer than 80 bytes due to 255 byte max message size.');
    }


    var pinBytesPadded = new Uint8Array(encLen);
    pinBytesPadded.fill(0);

    var i;
    for (i = 0; i < pinBytes.length; i++){
        pinBytesPadded[i] = pinBytes[i];
    }

    return pinBytesPadded;
}

var set_pin_ = function(pin, failAuth, func){
    var subcmd = PIN.setPin;

    var pinBytesPadded = pin2bytes(pin);
    var encLen = pinBytesPadded.length;

    var iv = new Uint8Array(16);
    iv.fill(0);

    var aesCbc = new aesjs.ModeOfOperation.cbc(this.shared_secret, iv);
    pinEnc = aesCbc.encrypt(pinBytesPadded);

    var pinAuth = computePinAuthRaw(this.shared_secret, pinEnc);

    if (func == undefined && typeof failAuth == 'function'){
        func = failAuth;
        failAuth = false;
    }

    if (failAuth){
        pinAuth.fill(0xAA);
        pinEnc.fill(0xAA);
    }

    var ourPubkey = this.platform_keypair.getPublic(undefined, 'hex');
    var ourPubkeyBytes = hex2array(ourPubkey.slice(2,ourPubkey.length));

    var req = pinRequestFormat(subcmd, pinAuth, ourPubkeyBytes, pinEnc);

    send_msg(req, function(resp){
        if (func) func(resp);
    });
}

var is_pin_set_ = function(func)
{
    this.set_pin('12345', true, function(resp){
        if (resp.status == "CTAP2_ERR_NOT_ALLOWED") {
            func({data:true, status: 'CTAP1_SUCCESS'});
        }
        else if (resp.status == "CTAP2_ERR_PIN_AUTH_INVALID"){
            func({data:false, status: 'CTAP1_SUCCESS'});
        }
        else {
            func({data: undefined, status: resp.status});
            //throw new Error("Device returned expected status: " + stat);
        }
    });
}

var change_pin_ = function(curpin, newpin, func, failAuth){
    var subcmd = PIN.changePin;

    pin2bytes(curpin);  // validation only

    var pinBytesPadded = pin2bytes(newpin);
    var encLen = pinBytesPadded.length;


    var iv = new Uint8Array(16);
    iv.fill(0);

    var aesCbc = new aesjs.ModeOfOperation.cbc(this.shared_secret, iv);
    newPinEnc = aesCbc.encrypt(pinBytesPadded);

    var hash = sha256.create();
    hash.update(toUTF8Array(curpin));
    curPinHash = hash.array().slice(0,16);

    aesCbc = new aesjs.ModeOfOperation.cbc(this.shared_secret, iv);
    curPinHashEnc = aesCbc.encrypt(curPinHash);

    var concat = new Uint8Array(newPinEnc.length + curPinHashEnc.length);
    concat.set(newPinEnc);
    concat.set(curPinHashEnc, newPinEnc.length);

    var pinAuth = computePinAuthRaw(this.shared_secret, concat);

    var ourPubkey = this.platform_keypair.getPublic(undefined, 'hex');
    var ourPubkeyBytes = hex2array(ourPubkey.slice(2,ourPubkey.length));

    var req = pinRequestFormat(subcmd, pinAuth, ourPubkeyBytes, newPinEnc, curPinHashEnc);

    send_msg(req, function(resp){
        if (func) func(resp);
    });
}

var get_retries_ = function(func){
    var subcmd = PIN.getRetries;

    var req = pinRequestFormat(subcmd);

    send_msg(req, function(resp){
        resp.data = resp.data[0];
        if (func) func(resp);
    });
}

var sign_ = function(obj, func){

    if (!obj.challenge)
        throw new Error("Need something to sign");

    var alg = obj.alg || 3;

    var pinToken = this.pinToken || undefined;

    var req = signRequestFormat(alg,pinToken,obj.challenge,obj.keyid);

    send_msg(req, function(resp){
        if (resp.status == 'CTAP1_SUCCESS') {
            var r = resp.data.slice(0,32);
            var s = resp.data.slice(32,64);
            r = array2hex(r);
            s = array2hex(s);
            resp.sig = {};
            resp.sig.r = r;
            resp.sig.s = s;
        }


        if (func) func(resp);
    });
};

var register_ = function(wifkey, func){

    if (!wifkey)
        throw new Error("No key provided");


    var req = registerRequestFormat(wifkey,this.pinToken);

    send_msg(req, function(resp){
        if (func) func(resp);
    });
};

// @note authorization required beforehand if device is not already locked.
var reset_ = function(func){

    var pinAuth = undefined;

    if (this.pinToken) {
        pinAuth = computePinAuth(this.pinToken, CMD.reset, 0, 0);
    }

    var req = formatRequest(CMD.reset,0,0, pinAuth);

    var self = this;

    send_msg(req, function(resp){
        if (resp.status == "CTAP1_SUCCESS")
        {
            self.init(function(resp){
                if (func)func(resp);
            });
        }
        else {
            if (func) func(resp);
        }
    });
};


// Read 72 random bytes from hardware RNG on device
var get_rng_ = function(func){

    var pinAuth = undefined;

    if (this.pinToken) {
        pinAuth = computePinAuth(this.pinToken, CMD.rng, 0, 0);
    }

    var req = formatRequest(CMD.rng,0,0, pinAuth);

    var self = this;

    send_msg(req, function(resp){
        if (func)func(resp);
    });
};

// Derive public key from the private key stored on device.  Returns X,Y point.  64 bytes.
var get_pubkey_ = function(func){

    var pinAuth = undefined;

    if (this.pinToken) {
        pinAuth = computePinAuth(this.pinToken, CMD.pubkey, 0, 0);
    }

    var req = formatRequest(CMD.pubkey,0,0, pinAuth);

    var self = this;

    send_msg(req, function(resp){
        if (func)func(resp);
    });
};

var is_bootloader_ = function(func){

    var req = formatBootRequest(CMD.boot_check);

    var self = this;

    send_msg(req, function(resp){
        if (func)func(resp);
    });
};

var bootloader_finish_ = function(sig,func){

    var req = formatBootRequest(CMD.boot_done, 0x8000, sig);

    send_msg(req, function(resp){
        if (func)func(resp);
    });
};

var bootloader_write_ = function(addr,data,func){

    var req = formatBootRequest(CMD.boot_write,addr,data);

    send_msg(req, function(resp){
        if (func)func(resp);
    });
};


function wrap_promise(func)
{
    var self = this;
    return function (){
        var args = arguments;
        return new Promise(function(resolve,reject){
            var i;
            var oldfunc = null;
            for (i = 0; i < args.length; i++)
            {
                if (typeof args[i] == 'function')
                {
                    oldfunc = args[i];
                    args[i] = function(){
                        oldfunc.apply(self,arguments);
                        resolve.apply(self,arguments);
                    };
                    break;
                }
            }
            if (oldfunc === null)
            {
                args = Array.prototype.slice.call(args);
                args.push(function(){
                        resolve.apply(self,arguments);
                    });
            }
            func.apply(self,args);
        });
    }
}

var get_firmware_http = wrap_promise(get_firmware_http_);

function WalletDevice() {
    var self = this;
    this.shared_secret = null;
    this.ec256k1 = new EC('secp256k1');
    this.ecp256 = new EC('p256');


    this.init = function(func){
        self.get_version(function(ver){
            self.version = ver;
            self.get_shared_secret(function(resp){
                if (resp.status == "CTAP1_SUCCESS") self.shared_secret = resp.data;
                else {
                }
                if (func) func(resp);
            });
        });
    };


    this.get_version = function(func){
        var req = formatRequest(CMD.version,0,0);
        send_msg(req, function(resp){
            var ver = new TextDecoder("utf-8").decode(resp.data);
            if (func) func(ver);
        });
    };

    this.get_shared_secret = get_shared_secret_;

    // getPinToken using set pin
    this.authenticate = authenticate_;

    this.sign = sign_;

    this.set_pin = set_pin_;

    this.is_pin_set = is_pin_set_;

    this.change_pin = change_pin_;

    this.get_retries = get_retries_;

    this.register = register_;

    this.reset = reset_;

    this.get_rng = get_rng_;

    this.get_pubkey = get_pubkey_;

    this.is_bootloader = is_bootloader_;

    this.bootloader_write = bootloader_write_;

    this.bootloader_finish = bootloader_finish_;

    this.init = wrap_promise.call(this, this.init);
    this.get_version = wrap_promise.call(this, this.get_version);
    this.get_shared_secret = wrap_promise.call(this, this.get_shared_secret );
    this.authenticate = wrap_promise.call(this,this.authenticate );
    this.sign = wrap_promise.call(this, this.sign );
    this.set_pin = wrap_promise.call(this,this.set_pin );
    this.is_pin_set = wrap_promise.call(this, this.is_pin_set );
    this.change_pin = wrap_promise.call(this, this.change_pin );
    this.get_retries = wrap_promise.call(this, this.get_retries );
    this.register = wrap_promise.call(this, this.register );
    this.reset = wrap_promise.call(this,this.reset );
    this.get_rng = wrap_promise.call(this,this.get_rng);
    this.get_pubkey = wrap_promise.call(this,this.get_pubkey);
    this.is_bootloader = wrap_promise.call(this,this.is_bootloader);
    this.bootloader_write = wrap_promise.call(this,this.bootloader_write);
    this.bootloader_finish = wrap_promise.call(this,this.bootloader_finish);

}

async function handleFirmware(files)
{
    var dev = new WalletDevice();

    var p = await dev.is_bootloader();

    document.getElementById('errors').textContent = '';
    if (p.status != 'CTAP1_SUCCESS')
    {
        document.getElementById('errors').textContent = 'Make sure device is in bootloader mode.  Unplug, hold button, plug in, wait for flashing yellow light.';
        return;
    }

    var reader = new FileReader();
    reader.onload = async function(ev){
        var resp = JSON.parse(ev.target.result);
        resp.firmware = websafe2string(resp.firmware);

        console.log(resp);
        var addr = 0x4000;
        var num_pages = 64;
        var sig = websafe2array(resp.signature);
        var badsig = websafe2array(resp.signature);
        badsig[40] = badsig[40] ^ 1;

        var blocks = MemoryMap.fromHex(resp.firmware);
        var addresses = blocks.keys();

        console.log(blocks);
        console.log(addresses);
        var addr = addresses.next();
        var chunk_size = 240;
        while(!addr.done) {
            var data = blocks.get(addr.value);
            var i;
            for (i = 0; i < data.length; i += chunk_size) {
                var chunk = data.slice(i,i+chunk_size);
                console.log('addr ',addr.value + i);
                p = await dev.bootloader_write(addr.value + i, chunk);

                TEST(p.status == 'CTAP1_SUCCESS', 'Device wrote data');
                var progress = (((i/data.length) * 100 * 100) | 0)/100;
                document.getElementById('progress').textContent = ''+progress+' %';
            }

            addr = addresses.next();
        }
        p = await dev.bootloader_finish(sig);
        if(p.status != 'CTAP1_SUCCESS')
        {
            document.getElementById('errors').textContent = 'Firmware image signature denied';
        }
        else
        {
            document.getElementById('errors').textContent = 'Update successful';
        }

    };

    reader.readAsText(files[0]);
}

function TEST(bool, test){
    if (bool) {
        if (test ) console.log("PASS: " + test);
    }
    else {
        console.log("FAIL: " + test);
        throw new Error("FAIL: " + test);
    }
}

async function run_tests() {

    var dev = new WalletDevice();
    var pin = "Conor's pin 👽 ";
    var pin2 = "sogyhdxoh3qwli😀";

    function string2challenge(chal) {
        var hash = sha256.create();
        hash.update(chal);
        chal = hash.array();
        return chal;
    }

    async function device_start_over()
    {

        var p = await dev.init();
        if (p.status == 'CTAP2_ERR_NOT_ALLOWED') {   // its already locked
            p = await dev.reset();
            TEST(p.status == "CTAP1_SUCCESS", 'Device reset');
            p = await dev.init();
            TEST(p.status == "CTAP1_SUCCESS", 'Device initialize');
        } else {
            TEST(p.status == "CTAP1_SUCCESS", 'Device initialize');

            //console.log(dev);

            TEST(dev.version == "WALLET_V1.0", 'Device reports right version');

            p = await dev.is_pin_set();
            TEST(p.status == "CTAP1_SUCCESS", 'Check if pin is set');

            if (!p.data) {
            } else {

                p = await dev.authenticate(pin);

                if (p.status == "CTAP2_ERR_PIN_INVALID" ) {
                    p = await dev.authenticate(pin2);     // try second pin
                }
                else {
                }

                TEST(p.status == "CTAP1_SUCCESS", 'Authenticated');
            }

            p = await dev.reset();
            TEST(p.status == "CTAP1_SUCCESS", 'Device reset');
        }
    }

    async function test_pin()
    {
        var p = await dev.is_pin_set();
        TEST(p.status == "CTAP1_SUCCESS" && !p.data, 'Pin is not set');

        p = await dev.set_pin(pin);
        TEST(p.status == "CTAP1_SUCCESS", 'A pin was set');

        p = await dev.is_pin_set();
        TEST(p.status == "CTAP1_SUCCESS" && p.data, 'Pin set is detected');

        p = await dev.set_pin(pin);
        TEST(p.status == "CTAP2_ERR_NOT_ALLOWED", 'Trying to set a pin again will fail');

        p = await dev.change_pin(pin, pin2);
        TEST(p.status == "CTAP1_SUCCESS", 'Going through change pin process is successful');

        p = await dev.authenticate(pin);
        TEST(p.status == "CTAP2_ERR_PIN_INVALID", 'Authenticating to previous/wrong pin is denied');

        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS" && p.data > 2, 'Have at least 2 tries left ('+p.data+')');
        var tries = p.data;

        p = await dev.authenticate(pin);
        TEST(p.status == "CTAP2_ERR_PIN_INVALID");

        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS" && (p.data > 1) && (p.data < tries),
            'Have less attempts left after another failed attempt (' + p.data+')');

        p = await dev.authenticate(pin2);
        TEST(p.status == "CTAP1_SUCCESS", 'Authenticating with correct pin success');

        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS" && p.data > tries, 'Retries reset ('+ p.data+')');

        p = await dev.change_pin(pin2, pin);
        TEST(p.status == "CTAP1_SUCCESS", 'Change pin back');

        // Reset device for next set of tests
        p = await dev.authenticate(pin);
        TEST(p.status == "CTAP1_SUCCESS");

        p = await dev.reset();
        TEST(p.status == "CTAP1_SUCCESS");

    }

    async function test_crypto(leaveEarly, startLate,imkey){
        var ec = new EC('secp256k1');
        key = imkey || ec.genKeyPair();

        var priv = key.getPrivate('hex');

        var wif = key2wif(priv);  // convert to wif

        // Corrupt 1 byte
        var b = (wif[32] == 'A') ? 'B' : 'A';
        var badwif = wif.substring(0, 32) + b + wif.substring(32+1);
        var p;

        var chal = string2challenge('abc');

        if (!startLate) {

            p = await dev.set_pin(pin);
            TEST(p.status == "CTAP1_SUCCESS");

            p = await dev.sign({challenge: chal});
            TEST(p.status == 'CTAP2_ERR_PIN_AUTH_INVALID', 'No signature without authenticating first');

            p = await dev.register(wif);
            TEST(p.status == 'CTAP2_ERR_PIN_AUTH_INVALID', 'No key register without authenticating first');

            p = await dev.get_rng();
            TEST(p.status == "CTAP2_ERR_PIN_AUTH_INVALID", 'No rng without authenticating first');

            p = await dev.authenticate(pin);
            TEST(p.status == "CTAP1_SUCCESS");

            p = await dev.sign({challenge: chal});
            TEST(p.status == 'CTAP2_ERR_NO_CREDENTIALS', 'No signature without key');

            p = await dev.register(badwif);
            TEST(p.status == 'CTAP2_ERR_CREDENTIAL_NOT_VALID', 'Wallet does not accept corrupted key');

            p = await dev.register(wif);
            TEST(p.status == 'CTAP1_SUCCESS', 'Wallet accepts good WIF key');

        } else {
            p = await dev.authenticate(pin + 'A');
            TEST(p.status == "CTAP2_ERR_PIN_INVALID", 'Wrong pin fails');

            p = await dev.authenticate(pin);
            TEST(p.status == "CTAP1_SUCCESS", 'Right pin works');
        }

        p = await dev.get_pubkey();
        TEST(p.status == 'CTAP1_SUCCESS', '(1) Wallet derives public key from stored private key');

        p = await dev.register(wif);
        TEST(p.status == 'CTAP2_ERR_KEY_STORE_FULL', 'Wallet does not accept another key');

        p = await dev.sign({challenge: chal});
        TEST(p.status == 'CTAP1_SUCCESS', 'Wallet returns signature');
        var sig = p.sig;

        var ver = key.verify(chal, sig);
        TEST(ver, 'Signature is valid');

        p = await dev.get_pubkey();
        TEST(p.status == 'CTAP1_SUCCESS', '(2) Wallet derives public key from stored private key');

        var key2 = ec.keyFromPublic('04'+array2hex(p.data), 'hex');
        ver = key2.verify(chal, sig);
        TEST(ver, 'Signature verifies with the derived public key');

        var count = p.count;
        p = await dev.sign({challenge: chal});
        ver = key.verify(chal, p.sig);
        TEST(p.status == 'CTAP1_SUCCESS' && p.count > count && ver, 'Count increments for each signature ' + p.count);

        if (leaveEarly) return;

        // Test lockout
        console.log("Exceeding all pin attempts...");
        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS");
        var tries = p.data;

        while (tries > 0) {
            p = await dev.authenticate('1234'); // wrong pin
            TEST(p.status == "CTAP2_ERR_PIN_INVALID");

            p = await dev.get_retries();
            TEST(p.status == "CTAP1_SUCCESS");
            tries = p.data;
        }

        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS");
        tries = p.data;
        TEST(tries == 0, 'Device has 0 tries left (lockout)');

        p = await dev.register(wif);
        TEST(p.status == 'CTAP2_ERR_PIN_AUTH_INVALID', 'Register is denied');

        p = await dev.sign({challenge: chal});
        TEST(p.status == 'CTAP2_ERR_PIN_AUTH_INVALID', 'Sign is denied');

        p = await dev.set_pin(pin);
        TEST(p.status == "CTAP2_ERR_NOT_ALLOWED", 'set_pin is locked out');

        p = await dev.change_pin(pin,pin2);
        TEST(p.status == "CTAP2_ERR_NOT_ALLOWED", 'change_pin is locked out');

        p = await dev.get_rng();
        TEST(p.status == "CTAP2_ERR_NOT_ALLOWED", 'get_rng is locked out');

        p = await dev.init();
        TEST(p.status == "CTAP2_ERR_NOT_ALLOWED", 'init (getKeyAgreement) is locked out');

        p = await dev.reset();
        TEST(p.status == "CTAP1_SUCCESS");

        p = await dev.get_retries();
        TEST(p.status == "CTAP1_SUCCESS");
        tries = p.data;

        p = await dev.is_pin_set();
        TEST(p.status == "CTAP1_SUCCESS");
        var is_pin_set = p.data;

        p = await dev.sign({challenge: chal});
        TEST(p.status == 'CTAP2_ERR_NO_CREDENTIALS');

        TEST(tries > 2 && is_pin_set == false, 'Device is no longer locked after reset and pin and key are gone');

        TEST(p.count >= count, 'Counter did not reset');
    }

    async function test_rng(){

        var pool = '';

        var p = await dev.get_rng();
        TEST(p.status == "CTAP1_SUCCESS", 'Rng responds');

        pool += array2hex(p.data);

        console.log("Gathering many RNG bytes..");

        while (pool.length < 1024 * 10) {
            var p = await dev.get_rng();
            TEST(p.status == "CTAP1_SUCCESS");
            pool += array2hex(p.data);
        }

        var entropy = shannon.entropy(pool) * 2;
        TEST(entropy > 7.99, 'Rng has good entropy: ' + entropy);
    }


    async function test_persistence()
    {

        var ec = new EC('secp256k1');
        var key = ec.keyFromPrivate('693e3c441129af84ed10693e3c441129af84ed10693e3c441129af84ed10aabb');
        var p = await dev.init();
        p = await dev.is_pin_set();
        TEST(p.status == "CTAP1_SUCCESS");
        var is_pin_set = p.data;
        if (! is_pin_set) {
            console.log("Pin is not set, resetting and loading new pin and key.");

            await device_start_over();
            await test_crypto(true,false,key);
            console.log("Now restart device and reload page.");
        } else {
            await test_crypto(true,true,key);
        }
    }

    async function benchmark()
    {
        var t1,t2,i;
        var ec = new EC('secp256k1');
        var key = ec.genKeyPair();
        var priv = key.getPrivate('hex');

        var wif = key2wif(priv);  // convert to wif

        var chal = string2challenge('abc');

        var p = await dev.register(wif);
        TEST(p.status == 'CTAP1_SUCCESS', 'Wallet accepts good WIF key');

        var count,lcount;
        lcount = -1;
        for (i = 0; i < 2048; i++)
        {
            t1 = performance.now();
            p = await dev.sign({challenge: chal});
            t2 = performance.now();
            var ver = key.verify(chal, p.sig);
            count = p.count;
            TEST(ver && p.status == 'CTAP1_SUCCESS', 'Wallet returns signature ('+(t2-t1)+' ms)');
            if (i != 0) TEST(count == (lcount+1), 'Count increased by 1 ('+count+')');

            lcount = count;
        }
    }

    async function test_bootloader()
    {
        var start = 10 * 2048;
        var size = 198 * 1024 - 8;
        var num_pages = 64;

        var p = await dev.is_bootloader();
        TEST(p.status == 'CTAP1_SUCCESS', 'Device is in bootloader mode');

        var randdata = new Uint8Array(16);

        p = await dev.bootloader_write(0, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies accessing invalid address');

        p = await dev.bootloader_write(start-4, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies accessing invalid address');

        p = await dev.bootloader_write(start, randdata);
        TEST(p.status == 'CTAP1_SUCCESS', 'Allows write to beginning');

        p = await dev.bootloader_write(start + size-16, randdata);
        TEST(p.status == 'CTAP1_SUCCESS', 'Allows write to end');

        p = await dev.bootloader_write(start + size-8, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies overflow');

        p = await dev.bootloader_write(start + size, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies accessing invalid address');

        p = await dev.bootloader_write(start + size + 1024, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies accessing invalid address');

        p = await dev.bootloader_write(start + size + 1024*10, randdata);
        TEST(p.status == 'CTAP2_ERR_NOT_ALLOWED', 'Denies accessing invalid address');

        var badsig = new Uint8Array(64);
        badsig[40] = badsig[40] ^ 1;

        p = await dev.bootloader_finish(badsig);
        TEST(p.status == 'CTAP2_ERR_OPERATION_DENIED', 'Device rejected new image with bad signature');

    }

    //while(1)
    {
        // await device_start_over();
        //await test_pin();
        // await test_crypto();
        //await test_rng();
    }
    //await benchmark();
    //await test_persistence();

    await test_bootloader();


}
var test;

EC = elliptic.ec

//run_tests()
