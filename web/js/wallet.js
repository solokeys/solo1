DEVELOPMENT = 1;

var to_b58 = function(B){var A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";var d=[],s="",i,j,c,n;for(i in B){j=0,c=B[i];s+=c||s.length^i?"":1;while(j in d||c){n=d[j];n=n?n*256+c:c;c=n/58|0;d[j]=n%58;j++}}while(j--)s+=A[d[j]];return s};
var from_b58 = function(S){var A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";var d=[],b=[],i,j,c,n;for(i in S){j=0,c=A.indexOf(S[i]);if(c<0)throw new Error('Invald b58 character');c||b.length^i?i:b.push(0);while(j in d||c){n=d[j];n=n?n*58+c:c;c=n>>8;d[j]=n%256;j++}}while(j--)b.push(d[j]);return new Uint8Array(b)};

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

// For real
function send_msg_u2f(data, func, timeout) {
    // Use key handle and signature response as comm channel
    var d = new Date();
    var t1 = d.getTime();
    timeout = timeout || 5;

    var appid = window.location.origin;
    var chal = string2websafe('AABBCC');

    var chal = array2websafe(hex2array('d1cd7357bcedc03fcec112fe5a7f3f890292ff6f758978928b736ce1e63479e5'));

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
    var len = 16 + 4 + argslen;

    if (len > 255)
    {
        throw new Error('Total length of request cannot exceed 255 bytes');
    }

    var array = new Uint8Array(len);

    array[0] = cmd & 0xff;
    array[1] = p1 & 0xff;
    array[2] = p2 & 0xff;
    array[3] = (args.length) & 0xff;

    if (pinAuth) {
        for (i = 0; i < 16; i += 1) {
            array[4 + i] = pinAuth[i];
        }
    }

    var offset = 4 + i;

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

    var pinAuth = computePinAuth(pinToken,cmd,p1,p2,args);
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

    var pinAuth = computePinAuth(pinToken,cmd,p1,p2,args);
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

        if (func) func(shared);

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
        var pinToken = aesCbc.decrypt(pinTokenEnc);
        self.pinToken = pinToken;
        if (func) func({pinToken: pinToken, status: resp.status});
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

var set_pin_ = function(pin, func, failAuth){
    var subcmd = PIN.setPin;

    var pinBytesPadded = pin2bytes(pin);
    var encLen = pinBytesPadded.length;

    var iv = new Uint8Array(16);
    iv.fill(0);

    var aesCbc = new aesjs.ModeOfOperation.cbc(this.shared_secret, iv);
    pinEnc = aesCbc.encrypt(pinBytesPadded);

    var pinAuth = computePinAuthRaw(this.shared_secret, pinEnc);

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
    this.set_pin('12345', function(resp){
        if (resp.status == "CTAP2_ERR_NOT_ALLOWED") {
            func(true);
        }
        else if (resp.status == "CTAP2_ERR_PIN_AUTH_INVALID"){
            func(false);
        }
        else {
            throw new Error("Device returned expected status: " + stat);
        }
    }, true);
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
        if (func) func(resp.status);
    });
}

var get_retries_ = function(func){
    var subcmd = PIN.getRetries;

    var req = pinRequestFormat(subcmd);

    send_msg(req, function(resp){
        if (func) func(resp.data[0]);
    });
}

var sign_ = function(obj, func){

    if (!obj.challenge)
        throw new Error("Need something to sign");

    var alg = obj.alg || 3;

    var req = signRequestFormat(alg,this.pinToken,obj.challenge,obj.keyid);

    send_msg(req, function(resp){

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

function wrap_promise(func)
{
    var self = this;
    return function (){
        var args = arguments;
        return new Promise(function(resolve,reject){
            var i;
            for (i = 0; i < args.length; i++)
            {
                if (typeof args[i] == 'function')
                {
                    var oldfunc = args[i];
                    args[i] = function(){
                        oldfunc.apply(self,arguments);
                        resolve.apply(self,arguments);
                        //oldfunc.call(arguments);
                        //resolve.call(arguments);
                    };
                    break;
                }
            }
            func.apply(self,args);
        });
    }
}

function WalletDevice() {
    var self = this;
    this.shared_secret = null;
    this.ec256k1 = new EC('secp256k1');
    this.ecp256 = new EC('p256');


    this.init = function(func){
        self.get_version(function(ver){
            self.version = ver;
            self.get_shared_secret(function(shared){
                self.shared_secret = shared;
                if (func) func();
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

    //this.init = wrap_promise(this.init);
    //this.get_version = wrap_promise(this.get_version);
    //this.get_shared_secret = wrap_promise(this.get_shared_secret );
    //this.authenticate = wrap_promise(this.authenticate );
    //this.sign = wrap_promise(this.sign );
    //this.set_pin = wrap_promise(this.set_pin );
    //this.is_pin_set = wrap_promise(this.is_pin_set );
    //this.change_pin = wrap_promise(this.change_pin );
    //this.get_retries = wrap_promise(this.get_retries );
    //this.register = wrap_promise(this.register );
    //this.reset = wrap_promise(this.reset );

}

async function run_tests() {

    var dev = new WalletDevice();
    var pin = "Conor's pin 👽 ";
    var pin2 = "sogyhdxoh3qwli😀";


    function device_start_over(next)
    {
        dev.init(function(resp){

            console.log('connected. version: ', dev.version);

            dev.is_pin_set(function(bool){
                if (bool) {
                    dev.authenticate(pin, function(resp){
                        //reset_device(next);
                    });
                }
                else {
                    //reset_device(next);
                }
            });

        
        });
    }

    function reset_device(func)
    {
        dev.reset(function(resp){
            console.log("reset: ",resp);
            if (func) func();
        });
    }

    function test_pin(next)
    {
        dev.set_pin(pin, function(resp){
            if (resp.status == "CTAP1_SUCCESS"){
                console.log('Set pin to ' + pin);
                dev.set_pin(pin, function(resp){
                
                });
            }
            else {
                console.log("Fail set_pin");
            }
        });
    }

    device_start_over();

    function t2 ()
    {
        var ec = new EC('p256');
        var key = ec.genKeyPair();

        var priv = key.getPrivate('hex');

        // convert to wif
        priv = key2wif(priv);

        var chal = 'ogfhriodghdro;igh';

        var hash = sha256.create();
        hash.update(chal);
        chal = hash.array();


        dev.register(priv, function(resp){
            console.log('register response', resp);
            dev.sign({challenge: chal}, function(resp){

                var r = resp.data.slice(0,32);
                var s = resp.data.slice(32,64);

                r = array2hex(r);
                s = array2hex(s);

                var sig = {r: r, s: s};

                console.log('sign response', resp);

                var ver = key.verify(chal, sig);

                console.log("verify: ",ver);

            });
        });
    }

}


EC = elliptic.ec

run_tests()

