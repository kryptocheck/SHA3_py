from typing import Literal, IO

try:
    from cffi import FFI
    possible_V4 = True
except ImportError:
    possible_V4 = False


from Keccak import Keccak, KeccakV2, KeccakV3, KeccakV4

class _SHA3:
    """
        Base class for SHA3 algorithms. For educational purposes only, do not use in production.
        Do not call instantiate directly.

        """

    def __init__(self,
                 implementation_version: int = 3
                 ) -> None:
        """
        Base class for SHA3 algorithms. For educational purposes only, do not use in production.
        Do not call instantiate directly.

        Args:
            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        match implementation_version:
            case 1:
                self._keccak_data["padding_algorithm"] = Keccak.pad10star1
                self.keccak_instance = Keccak(**self._keccak_data)
            case 2:
                self._keccak_data["padding_algorithm"] = KeccakV2.pad10star1
                self.keccak_instance = KeccakV2(**self._keccak_data)
            case 3:
                self._keccak_data["padding_algorithm"] = KeccakV3.pad10star1
                self.keccak_instance = KeccakV3(**self._keccak_data)
            case 4:
                if possible_V4:
                    self._keccak_data["padding_algorithm"] = KeccakV4.pad10star1
                    self.keccak_instance = KeccakV4(**self._keccak_data)
                else:
                    print("Cannot use v4 - install cffi module first. Switching to v3")
                    self._keccak_data["padding_algorithm"] = KeccakV3.pad10star1
                    self.keccak_instance = KeccakV3(**self._keccak_data)
            case _:
                self._keccak_data["padding_algorithm"] = Keccak.pad10star1
                self.keccak_instance = Keccak(**self._keccak_data)


        self.output: str = self.keccak_instance.output

    def update(self,
               input_data: str | bytes | list[Literal[0, 1]]
               ) -> None:
        """
        Takes input_text, preprocesses it and process as much input_buffer as possible without finalizing text


        Args:
            input_data:
                newly added input text

        """
        self.keccak_instance.update(input_data)

    def finalize(self,
                 input_data: str | bytes | list[Literal[0, 1]] = None
                 ) -> str:
        """
        Takes input_data, preprocesses it, adds optional domain separation bits and applies padding, then processes
        whole input_buffer


        Args:
            input_data:
                newly added input text

        Returns:
            hexstring result of computation

        """
        self.keccak_instance.finalize(input_data)
        self.output = self.keccak_instance.output
        return self.output


class SHA3_224(_SHA3):
    """
    Implementation of SHA3_224 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_224("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHA3_224 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 224,
                             "c" : 448,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [0, 1],
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)

class SHA3_256(_SHA3):
    """
    Implementation of SHA3_256 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_256("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHA3_256 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 256,
                             "c" : 512,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [0, 1],
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)



class SHA3_384(_SHA3):
    """
    Implementation of SHA3_384 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_384("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHA3_384 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 384,
                             "c" : 768,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [0, 1],
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)


class SHA3_512(_SHA3):
    """
    Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_512("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 512,
                             "c" : 1024,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [0, 1],
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)


class SHA3_512(_SHA3):
    """
    Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_512("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 512,
                             "c" : 1024,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [0, 1],
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)

class SHAKE_128(_SHA3):
    """
   Implementation of SHAKE_128 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHAKE_128("sample data", 800)
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 output_length: int,
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHAKE_128 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            output_length:
                requested length of the output of an XOF in bits.

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 128,
                             "c" : 256,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [1, 1, 1, 1],
                             "output_length": output_length,
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version = implementation_version)


class SHAKE_256(_SHA3):
    """
   Implementation of SHAKE_256 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHAKE_256("sample data", 800)
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0,1]],
                 output_length: int,
                 input_format: str="string",
                 output_intermediate_values: bool=False,
                 nist_format: bool=False,
                 implementation_version: int = 3
                 ) -> None:
        """
        Implementation of SHAKE_256 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values.

        If nist_format is set, values are in format used here:
        https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

        Args:
            input_data:
                Optional data to process. If present, it automatically calls finalize().

            output_length:
                requested length of the output of an XOF in bits.

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            output_intermediate_values:
                If true, basic algorithm versions are used and file with intermediate values are created.
                If false, better algorithm versions are used and only output is produced.

            nist_format:
                Only relevant when output_intermediate_values.
                When True, exports intermediary values in SHA3 string format as stated in NIST example here:
                https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
                When False, exports intermediary values in regular HEX format.

                Example:
                    When True: 0101 1100 -> 3A
                    When False: 0101 1100 -> 5C

            implementation_version:
                What implementation of algorithm is actually used for computation? Possible values:
                    1 - 3D state array and as writen in standard. Only one that can be used with
                        output_intermediate_values
                    2 - 3D state array, some improvements for better speed
                    3 - 1D state array, my fastest pure python implementation
                    4 - 1D state array, internally calls my C implementation of SHA3 (default)
        """

        self._keccak_data = {"b": 1600,
                             "rounds" : 24,
                             "d" : 256,
                             "c" : 512,
                             "input_data" : input_data,
                             "input_format" : input_format,
                             "domain_separation_bits" : [1, 1, 1, 1],
                             "output_length": output_length,
                             "output_intermediate_values" : output_intermediate_values,
                             "nist_format": nist_format}

        super().__init__(implementation_version=implementation_version)
