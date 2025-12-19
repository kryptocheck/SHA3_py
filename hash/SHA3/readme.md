# SHA3 - My python implementation

My implementation of SHA-3 algorithm family based on Keccak algorithm as described in https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf.

Optionally **outputs intermediate values** of all rounds and all algorithms to file.

**FOR EDUCATIONAL PURPOSES ONLY**, not intended to be used in production.

## Basic usage

Call one of **SHA3_224**, **SHA3_256**, **SHA3_384**, **SHA3_512**, **SHAKE_128**, **SHAKE_256** functions. Parameters:
* **[string]** Text to be hashed.
* *(only for SHAKE)* **[int]** Expected output length in bits. 

Computed hash can be found in **output** attribute.
 
```python
from SHA3 import SHA3_224, SHAKE_128
sha_224 = SHA3_224("Text to be hashed")
print(sha_224.output)

shake128 = SHAKE_128("Text to be hashed", 120)
print(shake128.output)
```

Alternatively, when you want to supply input in parts, you can use update() and finalize() methods. In that case call SHA3 function with empty first parameter.
```python
from SHA3 import SHA3_224, SHAKE_128
sha_224 = SHA3_224("")
sha_224.update("Text to ")
sha_224.update("be ")
print(sha_224.finalize("hashed")) # finalize() directly returns output hash 
print(sha_224.output) # This still works as well

shake128 = SHAKE_128("", 120)
sha_224.update("Text to ")
sha_224.update("be ")
print(sha_224.finalize("hashed")) # finalize() directly returns output hash 
print(sha_224.output) # This still works as well
```

## Advanced usage
Implementation contains this additional functionality:

### Other input formats
There are multiple input types supported:
* **string** "example" *(default)*
* **byte** b"\x00\x01\x02"
* **hexstring** "65 78 61 6D 70 6C 65" (optional spaces)
* **bitstring** "01000101 01111000 01100001 01101101 01110000 01101100" (optional spaces)
* **bitarray**  [0, 1, 0, 0, 0, 1, 0, 1]
* **base64** "ZXhhbXBsZQ=="

To use any of these alternative input formats, use argument *input_format* with one of values from list above, when calling first method.

When combining with update() and finalize(), the same *input_format* as in initial call is expected.
```python
from SHA3 import SHA3_224

sha_224 = SHA3_224("65 78 61 6D 70 6C 65", input_format="hexstring")
print(sha_224.output) 

sha_224 = SHA3_224("", input_format="hexstring")
sha_224.update("65 78")
sha_224.update("61 6D")
print(sha_224.finalize("70 6C 65")) 
print(sha_224.output) 
```

### Exporting intermediate values
Intermediate values of all rounds and all algorithms can be printed into file. To do this, call initial function with *output_intermediate_values* set to **True**.

There are 2 ways these values can be formatted, to switch between them, use *nist_format* set to *True/False* :
* when set to *True*, it uses same format as examples here https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values.
* when set to *False*, it uses regular format 

Example (first 16 bits of state are **01001100 01100000**):
* *True*:  **32 06**
* *False*: **4C 60**

When used in combination with implementation_version = 3, returns line represented as 64bit big-endian integer (*nist_format* is ignored):
* 10000...0 (1 and 63 zeroes) = 1
* 00000...1 (63 zeroes and 1) = 9223372036854775808

Cannot be used in combination with implementation_version = 4 (can be called, but is ignored).

### Implementation version
There are actually 4 separate implementations of the same Keccak algorithm here (all returning same outputs).
* **Version 1**: Uses 3D state array (of individual bits) and implements algorithm as described without modifications. This is the most transparent implementation when you want to examine how algorithm works.
* **Version 2**: Still uses 3D state array, but implements some minor enhancements so all operations are actually computed in-place.
* **Version 3**: Uses 1D array of 64bit integers. Still pure python though.
* **Version 4**: Internally calls my own C implementation and returns result.

You can modify what implementation is actually used by calling function with parameter **implementation_version** = *1,2,3* or *4* respectively. 

```python
from SHA3 import SHA3_224

sha_224 = SHA3_224("65 78 61 6D 70 6C 65", input_format="hexstring", implementation_version = 1)
print(sha_224.output) 


```

#### Speed differences
Tested SHA3_224 with short string inputs 10 times each and computed average.

| Implementation | Average of 10 |
|----------------|---------------|
| 1              | 0.127s        |
| 2              | 0.035s        |
| 3              | 0.007s        |
| 4              | ?             |

