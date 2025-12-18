from base64 import b64decode
from typing import Literal, IO

class Keccak:

    POSSIBLE_B = {25: (1, 0),
                  50: (2, 1),
                  100: (4, 2),
                  200: (8, 3),
                  400: (16, 4),
                  800: (32, 5),
                  1600: (64, 6)}


    """
    Implementation of Keccak permutation based on https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf.


    Attributes:
        b:
            The width of a KECCAK-p permutation in bits. Possible values: [25, 50, 100, 200, 400, 800, 1600]
        
        w:
            The lane size of a KECCAK-p permutation in bits, i.e., b/25
        
        l:
            For a KECCAK-p permutation, the binary logarithm of the lane size, i.e., log2(w)
        
        rounds:
            Number of rounds for KECCAK-p permutation.
        
        c:
            The capacity of a sponge function.
            
        r:
            The rate of a sponge function.
        
        d:
            The length of the digest of a hash function in bits.

        output_length:
            requested length of the output of an XOF in bits.
        
        domain_separation_bits:
            Optional domain separation bits defined for versions of SHA3 algorithm
        
        padding_algortihm:
            Algorithm to use for padding or None, when message is already padded.
        
        input_buffer:
            Preprocessed input waiting for processing
        
        unfinished_byte:
            Input that is not ready for preprocessing yet

        input_format:
            Format of input data. Possible values:
                string: "example"
                byte: b"\x00\x01\x02"
                hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                base64: "ZXhhbXBsZQ=="

        output:
            Computed hash in form of hexstring
                   
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

        finalized:
            flag that means that hash is already computed and no computation shall continue

    """
    def __init__(self,
                 b: int,
                 rounds: int,
                 d: int,
                 c: int,
                 input_data : str | bytes | list[Literal[0,1]] = "",
                 input_format : str = "string",
                 domain_separation_bits: list[Literal[0,1]] = None,
                 padding_algorithm: callable = None,
                 output_length: int = 0,
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:

        """
        Initializes new instance of Keccak. If called with input_data, automatically finalizes and creates output.
        When called with empty input_data, only initializes, it is necessary to call update() and finalize() functions

        Args:
            b:
                The width of a KECCAK-p permutation in bits. Possible values: [25, 50, 100, 200, 400, 800, 1600]

            rounds:
                Number of rounds for KECCAK-p permutation.

            d:
                The length of the digest of a hash function in bits.

            c:
                The capacity of a sponge function.

            input_data:
                Optional data to process. If present, it automatically calls finalize().

            input_format:
                Format of input data. Possible values:
                    string: "example"
                    bytes: b"\x00\x01\x02"
                    hexstring: "65 78 61 6D 70 6C 65" (optional spaces)
                    bitstring: "01000101 01111000 01100001 01101101 01110000 01101100 01100101" (optional spaces)
                    bitarray: [0, 1, 0, 0, 0, 1, 0, 1]
                    base64: "ZXhhbXBsZQ=="

            domain_separation_bits:
                Array of domain separation bits (used for SHA3/SHAKE)

            padding_algorithm:
                Algorithm to use for padding. When empty, input_text have to be proper length (multiple of r)

            output_length:
                Requested length of the output of an XOF in bits.

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
        """


        if b in self.POSSIBLE_B:
            self._b : int = b
            self._w : int = self.POSSIBLE_B[b][0]
            self._l : int = self.POSSIBLE_B[b][1]
        else:
            raise ValueError(f"Impossible value for b: {b}. Possible values: [25, 50, 100, 200, 400, 800, 1600]")

        self._rounds: int = rounds

        self._c : int = c
        self._r : int = self._b - c
        self._d : int = d
        self._output_length : int = output_length

        if self._output_length % 8 != 0:
            raise NotImplementedError(f"Output of length not in full bytes not implemented")

        self._state_array: list[list[list[Literal[0,1]]]] = self._initialize_empty_array()

        self._input_format: str = input_format
        self._input_buffer: list[Literal[0,1]] = []
        self._unfinished_byte: str | list[Literal[0,1]]  = ""

        self.output: str = ""

        self._output_intermediate_values = output_intermediate_values
        self._nist_format = nist_format

        self._domain_separation_bits: list[Literal[0,1]]

        if domain_separation_bits:
            self._domain_separation_bits = domain_separation_bits
        else:
            self._domain_separation_bits = []

        self.padding_algorithm : callable = padding_algorithm

        self._finalized = False

        if input_data:
            self.finalize(input_data)



    def update(self,
               input_data: str | bytes | list[Literal[0,1]]
               ) -> None:
        """
        Takes input_text, preprocesses it and process as much input_buffer as possible without finalizing text


        Args:
            input_data:
                newly added input text

        """
        if self._finalized:
            raise ValueError(f"Already finalized")

        self._preprocess_input(input_data)

        while len(self._input_buffer) > self._r:
            self._merge_data_into_state_array()
            self._compute_all_rounds()


    def finalize(self,
                 input_data: str | bytes | list[Literal[0,1]] = None
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

        if self._finalized:
            raise ValueError(f"Already finalized")

        self._preprocess_input(input_data)

        self._finalize_input_buffer()

        file = None
        if self._output_intermediate_values:
            file = open("intermediate_values.txt", "w")


        permutation_count = 0
        while self._input_buffer:
            self._merge_data_into_state_array()
            if file:
                file.write(f"Permutation {permutation_count}\n")
                permutation_count += 1

            self._compute_all_rounds(file)



        if file:
            file.write("Squeezing output. \n")

        result_array = []

        result_array = self._extract_result(result_array)
        if self._output_length > 0:
            while len(result_array) < self._output_length:
                self._compute_all_rounds(file)
                result_array = self._extract_result(result_array)
                if file:
                    file.write(f"Permutation {permutation_count}\n")
                    permutation_count += 1

        self._compute_output(result_array)

        if file:
            file.close()

        self._finalized = True
        return self.output

    def _compute_output(self,
                        result_array: list[Literal[0, 1]]
                        )-> None:
        """
        Extracts result of required length and transform it into hexstring and writes in into self.output.
        Args:
            result_array:
                Prepared hexstring
        """

        if self._output_length:
            result_array = result_array[:self._output_length]
        else:
            result_array = result_array[:self._d]
        self.output = self.b2h(result_array)



    def _initialize_empty_array(self
                                ) -> list[list[list[Literal[0,1]]]]:
        """
        Creates empty state array (3-dimensional)


        Returns:
            empty state array

        """

        arr = []
        for x in range(5):
            arr.append([])
            for y in range(5):
                arr[x].append([])
                for z in range(self._w):
                    arr[x][y].append(0)
        return arr

    def _preprocess_input(self,
                          input_data: str | bytes | list[Literal[0,1]]
                          ) -> None:
        """
        Takes input data, transforms them into array of bits and append this array to _input_buffer

        Args:
            input_data:
                data to process

        Raises:
            ValueError:
                Format is not one of supported formats ["bitstring", "string", "hexstring", "bitarray", "base64"]
        """
        if input_data:
            match self._input_format:
                case "bitarray":
                    self._input_buffer += input_data[:]

                case "bitstring":
                    input_data = input_data.replace(" ", "").replace("\n", "")
                    self._input_buffer += [int(x) for x in input_data]

                case "hexstring":
                    input_data = input_data.replace(" ", "").replace("\n", "")
                    self._input_buffer += self.h2b(input_data)

                case "bytes":
                    self._input_buffer += self.h2b(input_data.hex())

                case "string":
                    hex_data = input_data.encode("utf-8").hex()
                    self._input_buffer += self.h2b(hex_data)

                case "base64":
                    input_data = self._unfinished_byte + input_data
                    self._unfinished_byte = ""

                    modcheck = len(input_data) % 4
                    if modcheck != 0:
                        self._unfinished_byte = input_data[-modcheck:]
                        input_data = input_data[:-modcheck]

                    hex_data = b64decode(input_data).hex()
                    self._input_buffer += self.h2b(hex_data)

                case _ :
                    raise ValueError(f"Unsupported input format: {self._input_format}")

    def _merge_data_into_state_array(self
                                     ) -> None:
        """
        Takes data of length self.r from self._input_buffer and merges them into state array.

        Raises:
            ValueError:
                When _input_buffer is shorter than self.r

        """
        if len(self._input_buffer) < self._r:
            raise ValueError(f"Input buffer is shorter that rate {len(self._input_buffer)} < {self._r}")

        data_to_merge = self._input_buffer[:self._r]
        self._input_buffer = self._input_buffer[self._r:]

        pos = 0
        while data_to_merge:
            x = pos % 5
            y = pos // 5
            lane_to_merge = data_to_merge[:self._w]
            data_to_merge = data_to_merge[self._w:]

            for z, bit in enumerate(lane_to_merge):
                self._state_array[x][y][z] = self.xor(self._state_array[x][y][z], bit)
            pos += 1

    def _write_state_array(self,
                           file: IO,
                           text: str
                           ) -> None:
        """
        Writes current intermediary values into file with provided text.


        Args:
            file:
                Handle of file to write to.

            text:
                Text to write along with intermediary values.



        """

        file.write(text + "\n\n")


        for y in range(5):
            for x in range(5):
                if self._nist_format:
                    row = self._state_array[x][y]

                    tmp_result = self.b2h(row)
                    result = ""
                    while tmp_result:
                        result += tmp_result[:2] + " "
                        tmp_result = tmp_result[2:]


                    file.write(f"({x},{y}): {result}\n")
                else:

                    rowstring = "".join([str(i) for i in self._state_array[x][y]])
                    result = ""
                    while rowstring:
                        this_byte = rowstring[:8]
                        rowstring = rowstring[8:]

                        tmp_result = hex(int(this_byte, 2))[2:]
                        if len(tmp_result) == 1:
                            tmp_result = "0" + tmp_result
                        result += tmp_result + " "

                    file.write(f"({x},{y}): {result.upper()}\n")

        file.write("\n")

    def _compute_all_rounds(self,
                            file: IO | None = None
                ) -> None:
        """
        Performs all rounds of Keccak-p permutation (sponge).

        Args:
            file:
                Handle of file to output intermediate values or None.

        """

        if self._output_intermediate_values:
            for round_index in range(self._rounds):
                self._write_state_array(file, f"Round {round_index} Before algorithm 1 ")
                self._algorithm_1()
                self._write_state_array(file, f"Round {round_index} After algorithm 1 ")
                self._algorithm_2()
                self._write_state_array(file, f"Round {round_index} After algorithm 2 ")
                self._algorithm_3()
                self._write_state_array(file, f"Round {round_index} After algorithm 3 ")
                self._algorithm_4()
                self._write_state_array(file, f"Round {round_index} After algorithm 4 ")
                self._algorithm_5(round_index)

            self._write_state_array(file, f"Final state ")

        else:
            for round_index in range(self._rounds):
                self._algorithm_1()
                self._algorithm_2()
                self._algorithm_3()
                self._algorithm_4()
                self._algorithm_5(round_index)


    def _finalize_input_buffer(self
                               ) -> None:
        """
        Applies domain separation bits and padding to input_buffer.

        """

        if self._unfinished_byte:
            raise ValueError(f"Some data could not be processed: {self._unfinished_byte}")

        self._input_buffer += self._domain_separation_bits
        if self.padding_algorithm:
            self.padding_algorithm(self)

        if len(self._input_buffer) % self._r != 0:
            raise ValueError(f"message not properly padded: input_buffer length = {len(self._input_buffer)}, r = {self._r} ")

    def _extract_result(self,
                        result_array: list[Literal[0, 1]]
                    )-> list[Literal[0, 1]]:
        """
        Extracts result of specified length from state array.

        Args:
            result_array:
                Result array being prepared.

        Return:
            Result array with another round processed.

        """

        new_result = []

        pos = 0
        while len(new_result) <= self._r:
            new_result += self._state_array[pos % 5][pos // 5]
            pos += 1

        new_result = new_result[:self._r]

        return result_array + new_result

    def pad10star1(self
                   ) -> None:
        """
        Padding algorithm 10*1 as defined in chapter 5.1.

        """

        j = (-len(self._input_buffer) - 2) % self._r
        self._input_buffer += [1] + [0]*j + [1]


    @staticmethod
    def xor(*args: int
            ) -> Literal[0,1]:
        """
        Takes all arguments in integer form and computer XOR of them (technically their sum modulo 2).

        Args:
            *args:
                Arguments to compute XOR from

        Returns:
            XOR result (0 or 1)

        """

        result = 0
        for a in args:
            result += a

        return result % 2

    @staticmethod
    def b2h(bit_array: list[Literal[0,1]]
            ) -> str:
        """
        b2h algorithm defined in Annex B.1. The formal bit-reordering function that was specified for the
        KECCAK submission to the SHA-3 competition

        Args:
            bit_array:
                Input bit array to transform to hexstring
        Returns:
            result in form of hexstring

        """
        transformation_table = {10: "A",
                                11: "B",
                                12: "C",
                                13: "D",
                                14: "E",
                                15: "F"}

        result = ""
        tmp_result = ""
        if len(bit_array) % 8 != 0:
            raise ValueError(f"Cannot create hexstring from bitstring length {len(bit_array)}")

        while bit_array:
            this = bit_array[:4]
            bit_array = bit_array[4:]

            bitsum = 0
            for i, b in enumerate(this):
                bitsum += b * 2**i

            if bitsum > 9:
                bitsum = transformation_table[bitsum]

            tmp_result = str(bitsum) + tmp_result

            if len(tmp_result) == 2:
                result += tmp_result
                tmp_result = ""

        return result


    @staticmethod
    def h2b(hexstring: str
            ) -> list[Literal[0,1]]:
        """
        h2b algorithm defined in Annex B.1. The conversion function from hexadecimal strings to the SHA-3 strings
        that they represent.


        Args:
            hexstring:
                hexstring to convert. Can contain spaces

        Returns:
            resulted bit array

        Raises:
            ValueError:
                input is not proper hexstring.

        """

        transformation_table = {"0": [0, 0, 0, 0],
                                "1": [1, 0, 0, 0],
                                "2": [0, 1, 0, 0],
                                "3": [1, 1, 0, 0],
                                "4": [0, 0, 1, 0],
                                "5": [1, 0, 1, 0],
                                "6": [0, 1, 1, 0],
                                "7": [1, 1, 1, 0],
                                "8": [0, 0, 0, 1],
                                "9": [1, 0, 0, 1],
                                "A": [0, 1, 0, 1],
                                "B": [1, 1, 0, 1],
                                "C": [0, 0, 1, 1],
                                "D": [1, 0, 1, 1],
                                "E": [0, 1, 1, 1],
                                "F": [1, 1, 1, 1]}

        bit_array: list[Literal[0,1]] = []
        tmp_array: list[Literal[0,1]] = []
        if len(hexstring) % 2 != 0:
            raise ValueError(f"Improper hexstring of length {len(hexstring)}")

        for i in hexstring:
            try:
                tmp_array = transformation_table[i.upper()] + tmp_array
            except KeyError:
                raise ValueError(f"Improper character in hexstring: {i}")

            if len(tmp_array) == 8:
                bit_array += tmp_array
                tmp_array = []

        return bit_array


    def _algorithm_1(self
                     ) -> None:
        """
        Algorithm θ as described in chapter 3.2.1
        The effect of θ is to XOR each bit in the state with the parities of two columns in the array.

        """

        new_array = self._initialize_empty_array()

        def C(x: int,
              z: int) -> Literal[0,1]:
            """
            XOR of values in specific column on coordinates [x,z].

            Args:
                x:
                    x coordinate of given column
                z:
                    z coordinate of given column

            Returns:
                result of xor of given column
            """

            result = 0
            for y in range(5):
                result = self.xor(result, self._state_array[x][y][z])

            return result

        def D(x :int,
              z: int
              ) -> Literal[0,1]:
            """
            XOR of values of two nearby columns to column specified by [x,z] coordinates.

            Args:
                x:
                    x coordinate of given column
                z:
                    z coordinate of given column

            Returns:
                result of xor of given column

            """
            return C((x - 1) % 5, z) + C((x+1) % 5, (z - 1) % self._w)

        for x in range(5):
            for y in range(5):
                for z in range(self._w):
                    new_array[x][y][z] = self.xor(self._state_array[x][y][z], D(x,z))

        self._state_array = new_array

    def _algorithm_2(self
                     ) -> None:
        """
        Algorithm ρ as described in chapter 3.2.2
        The effect of ρ is to rotate the bits of each lane by a length, called the offset, which depends on
        the fixed x and y coordinates of the lane

        """

        x = 1
        y = 0
        for t in range(24):
            offset = int((t + 1) * (t + 2)/2) % self._w
            self._state_array[x][y] = self._state_array[x][y][-offset:] + self._state_array[x][y][:-offset]
            x, y = y, (2*x + 3*y) % 5

    def _algorithm_3(self
                     ) -> None:
        """
        Algorithm π as described in chapter 3.2.3
        The effect of π is to rearrange the positions of the lanes.

        """

        new_state = []
        for x in range(5):
            new_state.append([])
            for y in range(5):
                new_state[x].append([])

        for x in range(5):
            for y in range(5):
                new_state[x][y] = self._state_array[(x + 3 * y) % 5][x]

        self._state_array = new_state

    def _algorithm_4(self
                        ) -> None:
        """
        Algorithm χ as described in chapter 3.2.4
        The effect of χ is to XOR each bit with a non-linear function of two other bits in its row
        """

        new_state = self._initialize_empty_array()

        for x in range(5):
            for y in range(5):
                for z in range(self._w):
                    new_state[x][y][z] = self.xor(self._state_array[x][y][z], (
                                (self._state_array[(x + 1) % 5][y][z] + 1) * (self._state_array[(x + 2) % 5][y][z])))

        self._state_array = new_state


    def _algorithm_5(self,
                     ir: int
                     ) -> None:
        """
        Algorithm ι as described in chapter 3.2.5
        The effect of ι is to modify some of the bits of Lane (0, 0) in a manner that depends on the round index ir.

        Args:
            ir:
                Round index

        """

        def rc(t: int
               ) -> Literal[0,1]:
            """
            Each of these l + 1 round constant bits is generated by a function that is based on
            a linear feedback shift register.

            Args:
                t:
                    input parameter for rc function

            Returns:
                one bit result value

            """

            if t % 255 == 0:
                return 1
            r = [1, 0, 0, 0, 0, 0, 0, 0]
            for i in range(t % 255):
                r.insert(0,0)
                r[0] = self.xor(r[0], r[8])
                r[4] = self.xor(r[4], r[8])
                r[5] = self.xor(r[5], r[8])
                r[6] = self.xor(r[6], r[8])
                r.pop()

            return r[0]

        RC = []
        for _ in range(self._w):
            RC.append(0)

        for j in range(self._l+1):
            RC[2**j - 1] = rc(j + 7*ir)

        for z in range(self._w):
            self._state_array[0][0][z] = self.xor(self._state_array[0][0][z], RC[z])




class KeccakV2(Keccak):
    def __init__(self,
                 b: int,
                 rounds: int,
                 d: int,
                 c: int,
                 input_data: str | bytes | list[Literal[0, 1]] = "",
                 input_format: str = "string",
                 domain_separation_bits: list[Literal[0, 1]] = None,
                 padding_algorithm: callable = None,
                 output_length: int = 0,
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        super().__init__(b=b,
                         rounds=rounds,
                         d=d,
                         c=c,
                         input_data=input_data,
                         input_format=input_format,
                         domain_separation_bits=domain_separation_bits,
                         padding_algorithm=padding_algorithm,
                         output_length=output_length,
                         output_intermediate_values=output_intermediate_values,
                         nist_format=nist_format)

    def _algorithm_1(self
                     ) -> None:
        """
                Alternative version of algorithm θ.
                Precomputes parity values for all columns and then do in-place XOR

        """

        def compute_column_parity(x: int,
                                  z: int
                                  ) -> Literal[0, 1]:
            """
            XOR of values in specific column on coordinates [x,z].

            Args:
                x:
                    x coordinate of given column
                z:
                    z coordinate of given column

            Returns:
                result of xor of given column
            """

            result = 0
            for y in range(5):
                result = self.xor(result, self._state_array[x][y][z])
            return result


        column_parity = []
        for x in range(5):
            column_parity.append([])
            for z in range(self._w):
                column_parity[x].append(compute_column_parity(x,z))

        for x in range(5):
            for y in range(5):
                for z in range(self._w):
                    self._state_array[x][y][z] = self.xor(self._state_array[x][y][z], column_parity[(x - 1) % 5][z], column_parity[(x + 1) % 5][(z - 1) % self._w])

    def _algorithm_2(self
                     ) -> None:
        """
        Alternative version of algorithm ρ
        Uses precomputed values for all columns offset

        """

        offset_table = [0, 36, 3, 105, 210,
                        1, 300, 10, 45, 66,
                        190, 6, 171, 15, 253,
                        28, 55, 153, 21, 120,
                        91, 276, 231, 136, 78]


        for t in range(1, 25):
            x = t // 5
            y = t % 5
            offset = -(offset_table[t] % self._w)
            self._state_array[x][y] = self._state_array[x][y][offset:] + self._state_array[x][y][:offset]

    def _algorithm_3(self
                     ) -> None:
        """
        Alternative version of algorithm π.
        Uses precomputed permutation table so can be processed in-place.

        """
        permutations = [(3, 0), (3, 3), (2, 3), (1, 2), (2, 1), (0, 2), (1, 0), (1, 1), (4, 1), (2, 4), (4, 2), (0, 4),
                        (2, 0), (2, 2), (3, 2), (4, 3), (3, 4), (0, 3), (4, 0), (4, 4), (1, 4), (3, 1), (1, 3)]

        start = self._state_array[0][1]

        current = (0, 1)

        while permutations:
            next_p = permutations.pop(0)
            self._state_array[current[0]][current[1]] = self._state_array[next_p[0]][next_p[1]]
            current = next_p

        self._state_array[1][3] = start


    def _algorithm_4(self
                     ) -> None:
        """
        Alternative version of algorithm χ
        State is processed in-place.

        """

        for y in range(5):
            for z in range(self._w):
                first_x = self._state_array[0][y][z]
                second_x = self._state_array[1][y][z]
                for x in range(3):
                    self._state_array[x][y][z] = self.xor(self._state_array[x][y][z], (
                                (self._state_array[(x + 1) % 5][y][z] + 1) * (self._state_array[(x + 2) % 5][y][z])))
                self._state_array[3][y][z] = self.xor(self._state_array[3][y][z], (
                        (self._state_array[4][y][z] + 1) * first_x))
                self._state_array[4][y][z] = self.xor(self._state_array[4][y][z], (
                        (first_x + 1) * second_x))

    def _algorithm_5(self,
                     ir: int
                     ) -> None:
        """
        Alternative version of algorithm ι
        Uses precomputed table.

        Args:
            ir:
                Round index

        """
        rc_table = [[1, 0, 0, 0, 0, 0, 0],
                    [0, 1, 0, 1, 1, 0, 0],
                    [0, 1, 1, 1, 1, 0, 1],
                    [0, 0, 0, 0, 1, 1, 1],
                    [1, 1, 1, 1, 1, 0, 0],
                    [1, 0, 0, 0, 0, 1, 0],
                    [1, 0, 0, 1, 1, 1, 1],
                    [1, 0, 1, 0, 1, 0, 1],
                    [0, 1, 1, 1, 0, 0, 0],
                    [0, 0, 1, 1, 0, 0, 0],
                    [1, 0, 1, 0, 1, 1, 0],
                    [0, 1, 1, 0, 0, 1, 0],
                    [1, 1, 1, 1, 1, 1, 0],
                    [1, 1, 1, 1, 0, 0, 1],
                    [1, 0, 1, 1, 1, 0, 1],
                    [1, 1, 0, 0, 1, 0, 1],
                    [0, 1, 0, 0, 1, 0, 1],
                    [0, 0, 0, 1, 0, 0, 1],
                    [0, 1, 1, 0, 1, 0, 0],
                    [0, 1, 1, 0, 0, 1, 1],
                    [1, 0, 0, 1, 1, 1, 1],
                    [0, 0, 0, 1, 1, 0, 1],
                    [1, 0, 0, 0, 0, 1, 0],
                    [0, 0, 1, 0, 1, 1, 1]]


        for z in range(self._l+1):
            self._state_array[0][0][(2**z)-1] = self.xor(self._state_array[0][0][(2**z)-1], rc_table[ir][z])


class KeccakV3(Keccak):
    def __init__(self,
                 b: int,
                 rounds: int,
                 d: int,
                 c: int,
                 input_data: str | bytes | list[Literal[0, 1]] = "",
                 input_format: str = "string",
                 domain_separation_bits: list[Literal[0, 1]] = None,
                 padding_algorithm: callable = None,
                 output_length: int = 0,
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:

        self._current_pos: int = 0
        self._state_array: list[int]
        super().__init__(b = b,
                         rounds= rounds,
                         d = d,
                         c = c,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = domain_separation_bits,
                         padding_algorithm = padding_algorithm,
                         output_length = output_length,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)



    def _initialize_empty_array(self
                                ) -> list[int]:
        """
        Creates empty state array (1-dimensional)


        Returns:
            empty state array

        """

        arr = []
        for x in range(25):
            arr.append(0)
        return arr

    def _preprocess_input(self,
                          input_data: str | bytes | list[Literal[0,1]]
                          ) -> None:
        """
        Takes input data, transforms them into array of bits and append this array to _input_buffer

        Args:
            input_data:
                data to process

        Raises:
            ValueError:
                Format is not one of supported formats ["bitstring", "string", "hexstring", "bitarray", "base64"]
        """
        if not self._input_buffer:
            self._input_buffer.append(0)

        if input_data:
            match self._input_format:
                case "string":
                    for c in input_data:
                        self._input_buffer[-1] ^= (ord(c) << self._current_pos)
                        self._current_pos += 8

                        if self._current_pos > 56:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                case "hexstring":
                    input_data = input_data.replace(" ","")
                    while input_data:
                        c = input_data[:2]
                        input_data = input_data[2:]

                        self._input_buffer[-1] ^= (int(c, 16) << self._current_pos)
                        self._current_pos += 8

                        if self._current_pos > 56:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                case "bytes":
                    for c in input_data:
                        self._input_buffer[-1] ^= (c << self._current_pos)
                        self._current_pos += 8

                        if self._current_pos > 56:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                case "base64":
                    input_data = self._unfinished_byte + input_data
                    self._unfinished_byte = ""

                    modcheck = len(input_data) % 4
                    if modcheck != 0:
                        self._unfinished_byte = input_data[-modcheck:]
                        input_data = input_data[:-modcheck]

                    data = b64decode(input_data)
                    for c in data:
                        self._input_buffer[-1] ^= (c << self._current_pos)
                        self._current_pos += 8

                        if self._current_pos > 56:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                case "bitarray":
                    input_data = input_data[:]
                    if self._unfinished_byte:
                        input_data = self._unfinished_byte + input_data

                    while input_data:
                        c = input_data.pop(0)
                        self._input_buffer[-1] ^= (c << self._current_pos)
                        self._current_pos += 1

                        if self._current_pos > 63:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                    self._unfinished_byte = input_data

                case "bitstring":
                    input_data = input_data.replace(" ", "")
                    if self._unfinished_byte:
                        input_data = self._unfinished_byte + input_data

                    divider = 8*(len(input_data)//8)

                    self._unfinished_byte = input_data[divider:]
                    input_data = input_data[:divider]

                    for c in input_data:
                        self._input_buffer[-1] ^= (int(c) << self._current_pos)
                        self._current_pos += 1

                        if self._current_pos > 63:
                            self._current_pos = 0
                            self._input_buffer.append(0)

                case _ :
                    raise ValueError(f"Unsupported input format: {self._input_format}")


    def _write_state_array(self,
                           file: IO,
                           text: str
                           ) -> None:
        """
        Writes current intermediary values into file with provided text.


        Args:
            file:
                Handle of file to write to.

            text:
                Text to write along with intermediary values.



        """

        file.write(text + "\n\n")


        for k in range(25):
                file.write(f"({k}): {self._state_array[k]}\n")

        file.write("\n")

    def _merge_data_into_state_array(self
                                     ) -> None:
        """
        Takes data of length self.r from self._input_buffer and merges them into state array.

        Raises:
            ValueError:
                When _input_buffer is shorter than self.r

        """
        if len(self._input_buffer) < self._r//64:
            raise ValueError(f"Input buffer is shorter that rate {len(self._input_buffer)*64} < {self._r}")

        for i in range(self._r//64):
            self._state_array[i] ^= self._input_buffer.pop(0)

    def _finalize_input_buffer(self
                               ) -> None:
        """
        Applies domain separation bits and padding to input_buffer.

        """

        if self._input_format == "base64" and self._unfinished_byte:
            raise ValueError(f"Some data could not be processed: {self._unfinished_byte}")



        data_lists = [self._unfinished_byte, self._domain_separation_bits]

        for l in [l for l in data_lists if l]:
            for x in l:
                self._input_buffer[-1] ^= (int(x) << self._current_pos)
                self._current_pos += 1

                if self._current_pos > 63:
                    self._current_pos = 0
                    self._input_buffer.append(0)

        self.padding_algorithm(self)

    def _compute_output(self,
                        result_array: list[int]
                        ) -> None:
        """
        Extracts result of required length and transform it into hexstring and writes in into self.output.
        Args:
            result_array:
                Prepared hexstring
        """

        if self._output_length:
            result_array = result_array[:self._output_length//8]
        else:
            result_array = result_array[:self._d//8]
        self.output = "".join([("0" + str(hex(r)[2:]).upper())[-2:] for r in result_array])

    def pad10star1(self
                   ) -> None:
        """
        Padding algorithm 10*1 as defined in chapter 5.1. This version directly applies it instead just returning padding.

        """
        self._input_buffer[-1] ^= (1 << self._current_pos)

        while len(self._input_buffer) % (self._r // 64) != 0:
            self._input_buffer.append(0)
        self._input_buffer[-1] ^= 9223372036854775808


    def _extract_result(self,
                        result_array: list[Literal[0, 1]]
                        )-> None:
        """
        Extracts result of specified length from state array.

        """

        new_array = []

        pos = 0
        while len(new_array) <= (self._r//8):
            number = self._state_array[pos]
            new_array += [(number >> (8 * i)) & 0xFF for i in range(8)]
            pos += 1

        new_array = new_array[:self._r//8]
        return result_array + new_array



    def _algorithm_1(self
                     ) -> None:
        """
                Alternative version of algorithm θ.
                Precomputes parity values for all columns and then do in-place XOR

        """

        column_parity = []
        for x in range(5):
            column_parity.append(0)
            for z in range(self._w):
                for y in range(5):
                    column_parity[x] ^= self._state_array[x + 5 * y] & (1 << z)

        for x in range(5):
            for y in range(5):
                    self._state_array[x + 5 * y] ^= column_parity[(x + 4) % 5] ^ ((column_parity[(x + 1) % 5] << 1 | column_parity[(x + 1) % 5]  >> 63) % 18446744073709551616)


    def _algorithm_2(self
                     ) -> None:
        """
        Alternative version of algorithm ρ
        Uses precomputed values for all columns offset

        """

        offset_table = [0, 63, 2, 36, 37,
                        28, 20, 58, 9, 44,
                        61, 54, 21, 39, 25,
                        23, 19, 49, 43, 56,
                        46, 62, 3, 8, 50]


        for t in range(1, 25):
            self._state_array[t] = ((self._state_array[t] >> offset_table[t]) | (self._state_array[t] << (64 - offset_table[t])) % 18446744073709551616)

    def _algorithm_3(self
                     ) -> None:
        """
        Alternative version of algorithm π.
        Uses precomputed permutation table so can be processed in-place.

        """
        permutations = [5, 3, 18, 17, 11, 7, 10, 1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16]

        start = self._state_array[5]

        for s in range(23):
            self._state_array[permutations[s]] = self._state_array[permutations[s + 1]]

        self._state_array[16] = start


    def _algorithm_4(self
                     ) -> None:
        """
        Alternative version of algorithm χ
        State is processed in-place.

        """

        for y in range(5):
            first_x = self._state_array[5 * y]
            second_x = self._state_array[5 * y + 1]

            for x in range(3):
                self._state_array[x + 5 * y] ^= ~self._state_array[x + 1 + 5 * y] & self._state_array[x + 2 + 5 * y]

            self._state_array[3 + 5 * y] ^= ~self._state_array[4 + 5 * y] & first_x
            self._state_array[4 + 5 * y] ^= ~first_x & second_x

    def _algorithm_5(self,
                     ir: int
                     ) -> None:
        """
        Alternative version of algorithm ι
        Uses precomputed table.

        Args:
            ir:
                Round index

        """
        round_constants = [1, 32898, 9223372036854808714, 9223372039002292224, 32907,
                           2147483649,  9223372039002292353, 9223372036854808585, 138, 136,
                           2147516425, 2147483658, 2147516555, 9223372036854775947, 9223372036854808713,
                           9223372036854808579, 9223372036854808578, 9223372036854775936, 32778, 9223372039002259466,
                           9223372039002292353, 9223372036854808704, 2147483649, 9223372039002292232]

        self._state_array[0] ^= round_constants[ir]


class KeccakV4(KeccakV3):
    def __init__(self):
        raise NotImplementedError("KeccakV4 not implemented")


class SHA3_224(KeccakV3):
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

        super().__init__(b = 1600,
                         rounds = 24,
                         d = 224,
                         c = 448,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = [0, 1],
                         padding_algorithm = self.pad10star1,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)


class SHA3_256(Keccak):
    """
    Implementation of SHA3_256 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_256("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """

    def __init__(self,
                 input_data: str | list[Literal[0, 1]],
                 input_format: str = "string",
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        """
        Implementation of SHA3_256 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values in the format used here:
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

        """

        super().__init__(b = 1600,
                         rounds = 24,
                         d = 256,
                         c = 512,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = [0, 1],
                         padding_algorithm = self.pad10star1,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)

class SHA3_384(Keccak):
    """
    Implementation of SHA3_384 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_384("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """

    def __init__(self,
                 input_data: str | list[Literal[0, 1]],
                 input_format: str = "string",
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        """
        Implementation of SHA3_384 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values in the format used here:
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

        """
        super().__init__(b = 1600,
                         rounds = 24,
                         d = 384,
                         c = 768,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = [0, 1],
                         padding_algorithm = self.pad10star1,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)

class SHA3_512(Keccak):
    """
    Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHA3_512("sample data")
        print (x.output)

    For advanced usage examples see README.md file.

    """

    def __init__(self,
                 input_data: str | list[Literal[0, 1]],
                 input_format: str = "string",
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        """
        Implementation of SHA3_512 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values in the format used here:
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

        """
        super().__init__(b = 1600,
                         rounds = 24,
                         d = 512,
                         c = 1024,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = [0, 1],
                         padding_algorithm = self.pad10star1,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)

class SHAKE_128(Keccak):
    """
    Implementation of SHAKE_128 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHAKE_128("sample data", 800)
        print (x.output)

    For advanced usage examples see README.md file.

    """

    def __init__(self,
                 input_data: str | list[Literal[0, 1]],
                 output_length: int,
                 input_format: str = "string",
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        """
        Implementation of SHAKE_128 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values in the format used here:
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

        """
        super().__init__(b = 1600,
                         rounds = 24,
                         d = 128,
                         c = 256,
                         input_data = input_data,
                         input_format = input_format,
                         domain_separation_bits = [1, 1, 1, 1],
                         padding_algorithm = self.pad10star1,
                         output_length = output_length,
                         output_intermediate_values = output_intermediate_values,
                         nist_format = nist_format)

class SHAKE_256(Keccak):
    """
    Implementation of SHAKE_256 algorithm. For educational purposes only, do not use in production.

    Basic usage:
        x = SHAKE_256("sample data", 800)
        print (x.output)

    For advanced usage examples see README.md file.

    """
    def __init__(self,
                 input_data: str | list[Literal[0, 1]],
                 output_length: int,
                 input_format: str = "string",
                 output_intermediate_values: bool = False,
                 nist_format: bool = False
                 ) -> None:
        """
        Implementation of SHAKE_256 algorithm. For educational purposes only, do not use in production.

        When output_intermediate_values is set to True, creates file with intermediate values in the format used here:
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

        """
        super().__init__(b = 1600,
                         rounds = 24,
                         d = 256,
                         c = 512,
                         input_data=input_data,
                         input_format=input_format,
                         domain_separation_bits=[1, 1, 1, 1],
                         padding_algorithm = self.pad10star1,
                         output_length=output_length,
                         output_intermediate_values=output_intermediate_values,
                         nist_format = nist_format)


