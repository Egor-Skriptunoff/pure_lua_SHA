# pure_lua_SHA

SHA-1, SHA-2 and SHA-3 functions written in pure Lua and optimized for speed.

---
### Installation

Just copy `sha2.lua` to Lua modules' folder.

---
### Description

This module provides functions to calculate SHA digest.  
This is a pure-Lua module, compatible with **Lua 5.1**, **Lua 5.2**, **Lua 5.3**, **Lua 5.4.0** (alpha), **LuaJIT 2.0/2.1** and **Fengari**.

Main feature of this module: it was heavily optimized for speed.  
For every Lua version the module contains particular implementation branch to get benefits from version-specific features.

Supported hashes:
```lua
MD5            -- sha.md5(message)
SHA-1          -- sha.sha1(message)
-- SHA2
SHA-224        -- sha.sha224(message)
SHA-256        -- sha.sha256(message)
SHA-384        -- sha.sha384(message)
SHA-512        -- sha.sha512(message)
SHA-512/224    -- sha.sha512_224(message)
SHA-512/256    -- sha.sha512_256(message)
-- SHA3
SHA3-224       -- sha.sha3_224(message)
SHA3-256       -- sha.sha3_256(message)
SHA3-384       -- sha.sha3_384(message)
SHA3-512       -- sha.sha3_512(message)
SHAKE128       -- sha.shake128(digest_size_in_bytes, message)
SHAKE256       -- sha.shake256(digest_size_in_bytes, message)
-- HMAC (applicable to any hash-function from this module except SHAKE)
HMAC           -- sha.hmac(sha.any_hash_func, key, message)
```
---
### Usage

Input data should be provided as a binary string: either as a whole string or as a sequence of substrings (chunk-by-chunk loading).  
Result (SHA digest) is returned in hexadecimal representation (as a string of lowercase hex digits).  

Simplest usage example:
```lua
local sha = require("sha2")
local your_hash = sha.sha256("your string")
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```
See file "sha2_test.lua" for more examples.

---
### FAQ
---

* **Q:** Does this module calculate SHA really fast?
* **A:**  
Probably, this is the fastest pure Lua implementation of SHA you can find.  
For example, on x64 Lua 5.3 this module calculates SHA256 twice as fast as the implementation published at [lua-users.org](http://lua-users.org/wiki/SecureHashAlgorithmBw)  
This module has best performance on every Lua version because it contains several version-specific implementation branches:  
   - branch for **Lua 5.1** (emulating bitwise operators using look-up table)
   - branch for **Lua 5.2** (using **bit32** library), suitable also for **Lua 5.1** with external **bit** library
   - branch for **Lua 5.3 / 5.4** (using native **64**-bit bitwise operators)
   - branch for **Lua 5.3 / 5.4** (using native **32**-bit bitwise operators) for Lua built with `LUA_INT_TYPE=LUA_INT_INT`
   - branch for **LuaJIT without FFI library** (if you're working in a sandboxed environment with FFI disabled)
   - branch for **LuaJIT x86 without FFI library** (LuaJIT x86 has oddity because of lack of x86 CPU registers)
   - branch for **LuaJIT 2.0 with FFI library** (`bit.*` functions work only with 32-bit values)
   - branch for **LuaJIT 2.1 with FFI library** (`bit.*` functions can work with `int64_t` cdata)

---
* **Q:** How to get SHA digest as binary string instead of hexadecimal representation?
* **A:**  
Use function `sha.hex2bin()` to convert hexadecimal to binary:
```lua
local sha = require("sha2")
local binary_hash = sha.hex2bin(sha.sha256("your string"))
-- assert(binary_hash == "\209Mi\29\172p\234\218\20\217\242>\248\0\145\188\161\199\\\247|\241\205\\\242\208A\128\202\r\153\17")
```

---
* **Q:** How to get SHA digest as base64 string?
* **A:**  
There are functions `sha.bin2base64()` and `sha.base642bin()` for converting between binary and base64:
```lua
local sha = require("sha2")
local binary_hash = sha.hex2bin(sha.sha256("your string"))
local base64_hash = sha.bin2base64(binary_hash)
-- assert(base64_hash == "0U1pHaxw6toU2fI++ACRvKHHXPd88c1c8tBBgMoNmRE=")
```

---
* **Q:** How to calculate SHA digest of long data stream?
* **A:**
```lua
local sha = require("sha2")
local append = sha.sha256()  -- if the "message" argument is omitted then "append" function is returned
append("your")
append(" st")                -- you should pass all parts of your long message to the "append" function (chunk-by-chunk)
append("ring")
local your_hash = append()   -- and finally ask for the result (by invoking the "append" function without argument)
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```

---
* **Q:** How to calculate HMAC-SHA1, HMAC-SHA256, etc. ?
* **A:**
```lua
-- Calculating HMAC-SHA1
local sha = require("sha2")
local your_hmac = sha.hmac(sha.sha1, "your key", "your message")
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```
The same in chunk-by-chunk mode (for long messages):
```lua
local sha = require("sha2")
local append = sha.hmac(sha.sha1, "your key")
append("your")
append(" mess")
append("age")
local your_hmac = append()
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```

---
* **Q:** Can SHAKE128/SHAKE256 be used to generate digest of infinite length ?
* **A:**  
Yes!  
For example, you can convert your password into infinite stream of pseudo-random bytes.  
Set `digest_size_in_bytes` to `-1` and obtain the function `get_next_part(part_size_in_bytes)`.  
Invoke this function repeatedly to get consecutive parts of the infinite digest.
```lua
local sha = require("sha2")
local get_next_part_of_digest = sha.shake128(-1, "The quick brown fox jumps over the lazy dog")
assert(get_next_part_of_digest(5) == "f4202e3c58") -- 5 bytes in hexadecimal representation
assert(get_next_part_of_digest()  == "52")         -- size=1 is assumed when omitted
assert(get_next_part_of_digest(0) == "")           -- size=0 is a valid size
assert(get_next_part_of_digest(4) == "f9182a04")   -- and so on to the infinity...
-- Note: you can use sha.hex2bin() to convert these hexadecimal parts to binary strings
-- By definition, the result of SHAKE with finite "digest_size_in_bytes" is just a finite prefix of "infinite digest":
assert(sha.shake128(4, "The quick brown fox jumps over the lazy dog")) == "f4202e3c")
```
For SHAKE, it's possible to combine "chunk-by-chunk" input mode with "chunk-by-chunk" output mode:
```lua
local sha = require("sha2")
local append_input_message = sha.shake128(-1)
append_input_message("The quick brown fox")
append_input_message(" jumps over")
append_input_message(" the lazy dog")
local get_next_part_of_digest = append_input_message()  -- input stream is terminated, now we can start receiving the output stream
assert(get_next_part_of_digest(5) == "f4202e3c58")
assert(get_next_part_of_digest(5) == "52f9182a04")      -- and so on...
```

---
* **Q:** Why does this module called "sha2.lua" despite of having implemented all SHA functions: SHA1, SHA2 and SHA3 ?
* **A:**  
Yes, the notation `local digest = require("sha2").sha3_512(message)` looks strange :-)  
The first release of this module contained only SHA2 functions, hence the name `sha2.lua`.  
But I can't rename the module due to backward-compatibility I've promised to keep forever (Was it a silly promise?)

---
### Backward-compatibility
This module will always keep backward-compatibility.  
If your program works successfully with some previous version of `sha2.lua`, it will also work with the latest version.
