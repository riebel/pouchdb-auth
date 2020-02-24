const crypto = {};

/**
 * Convert array of integers to a hex string.
 *
 * @param {number[]} array of integers
 * @return {string} HEX string
 */

function i2s(a) { // integer array to hex string
    for (var i = a.length; i--;) a[i] = ("0000000"+(a[i]>>>0).toString(16)).slice(-8)
    return a.join("")
}

/**
 * Convert string to an array of integers.
 *
 * @param {string}
 * @return {number[]} array of integers
 */

function s2i(s) { // string to integer array
    s = unescape(encodeURIComponent(s))
    var len = s.length
        , i = 0
        , bin = []

    while (i < len) {
        bin[i>>2] = s.charCodeAt(i++)<<24 |
            s.charCodeAt(i++)<<16 |
            s.charCodeAt(i++)<<8 |
            s.charCodeAt(i++)
    }
    bin.len = len
    return bin
}


//** HMAC
function hmac(hasher, key, txt, raw) {
    var len
        , i = 0
        , ipad = []
        , opad = []

    key = (key.length > 64) ? hasher(key, 1) : s2i(key)

    while (i < 16) {
        ipad[i] = key[i]^0x36363636
        opad[i] = key[i++]^0x5c5c5c5c
    }

    if (typeof txt == "string") {
        txt = s2i(txt)
        len = txt.len
    } else len = txt.length * 4
    i = hasher(opad.concat(hasher(ipad.concat(txt), 1, 64 + len)), 1)
    return raw ? i : i2s(i)
}

crypto.hmac = function(digest, key, message) {
    return hmac(crypto[digest], key, message)
}

//*/

/**
 * A minimum iteration count of 1,000 is recommended.
 * For especially critical keys,
 * or for very powerful systems
 * or systems where user-perceived performance is not critical,
 * an iteration count of 10,000,000 may be appropriate.
 *
 * PBKDF2 is always used with HMAC,
 * which is itself a construction which is built over
 * an underlying hash function.
 * So when we say "PBKDF2 with SHA-1",
 * we actually mean "PBKDF2 with HMAC with SHA-1".
 */

//** PBKDF2
// pbkdf2(sha256, this, salt, count, length || 32)
// crypto.pbkdf2('secret', 'salt', 4096, 512, 'sha256', function(err, key) {
// $PBKDF2$HMACSHA1:1000:akrvug==$Zi+c82tnjpcrRmUAHRd8h4ZRR5M=

crypto.pbkdf2 = crypto.pbkdf2Sync = pbkdf2

// crypto.pbkdf2('secret', 'salt', 4096, 512, 'sha256', function(err, key) {

function pbkdf2(secret, salt, count, length, digest, callback) {
    if (typeof digest == "function") {
        callback = digest
        digest = "sha1"
    }
    var hasher = crypto[digest] || crypto.sha1
    count = count || 1000

    var u, ui, i, j, k
        , out = []
        , wlen = length>>2 || 5

    for (k = 1; out.length < wlen; k++) {
        u = ui = hmac(hasher, secret, salt+String.fromCharCode(k >> 24 & 0xF, k >> 16 & 0xF, k >>  8 & 0xF, k  & 0xF), 1)

        for (i = count; --i;) {
            ui = hmac(hasher, secret, ui, 1)
            for (j = ui.length; j--;) u[j] ^= ui[j]
        }

        //out = out.concat(u)
        out.push.apply(out, u)
    }
    out = i2s(out).slice(0, length*2 || 40)
    if (callback) callback(null, out)
    else return out
}

//*/


function shaInit(bin, len) {
    if (typeof bin == "string") {
        bin = s2i(bin)
        len = bin.len
    } else len = len || bin.length<<2

    bin[len>>2] |= 0x80 << (24 - (31 & (len<<=3)))
    bin[((len + 64 >> 9) << 4) + 15] = len

    return bin
}

//** sha1
function l(x, n) { // rotate left
    return (x<<n) | (x>>>(32-n))
}

function sha1(data, raw, _len) {
    var a, b, c, d, e, t, j
        , i = 0
        , w = []
        , A = 0x67452301
        , B = 0xefcdab89
        , C = 0x98badcfe
        , D = 0x10325476
        , E = 0xc3d2e1f0
        , bin = shaInit(data, _len)
        , len = bin.length

    for (; i < len; i+=16, A+=a, B+=b, C+=c, D+=d, E+=e) {
        for (j=0, a=A, b=B, c=C, d=D, e=E; j < 80;) {
            w[j] = j < 16 ? bin[i+j] : l(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1)
            t = (j<20 ? ((b&c)|(~b&d))+0x5A827999 : j<40 ? (b^c^d)+0x6ED9EBA1 : j<60 ? ((b&c)|(b&d)|(c&d))+0x8F1BBCDC : (b^c^d)+0xCA62C1D6)+l(a,5)+e+(w[j++]|0)
            e = d
            d = c
            c = l(b,30)
            b = a
            a = t|0
        }
    }
    t = [A, B, C, D, E]
    return raw ? t : i2s(t)
}

crypto.sha1 = sha1
//*/

export default crypto;
