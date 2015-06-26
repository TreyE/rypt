require 'digest'
require 'base64'
require 'securerandom'

module Rypt
  # Implements the standard crypt(3) call with SHA-512 and a salt.
  # It consists of 3 main steps:
  #   1. Calculate an initial set of 'special' values from the salt and password
  #   2. Perform repeated stretching rounds using the 'special' values
  #   3. Finalize the hash result by reordering the bytes and base-64 encoding them using a custom mapping scheme
  # At the end we are going to take the result of #3 and spit it out concatenated with the seed as the final result.
  class Sha512
    def self.encrypt(plain)
      self.new.encrypt(plain)
    end

    def self.compare(encrypted, plain)
      encryptor = self.new
      salt = encryptor.extract_salt(encrypted)
      return false unless salt
      encrypted == self.new.run(salt, plain)
    end

    def extract_salt(encrypted)
      encrypted.split("$")[2]
    end

    def init_hash(salt, pass)
      alt_sum = Digest::SHA2.new(512).digest(pass + salt + pass)
      s_length = [salt.length, 16].min
      p_length = [pass.length, 64].min
      int_sum_input = pass + salt + alt_sum[0..(p_length - 1)]
      p_length_array = p_length.to_s(2)
      p_length_array.reverse.each_char do |c|
        if (c == "1")
          int_sum_input << alt_sum
        else
          int_sum_input << pass
        end
      end
      intermediate_0 = Digest::SHA2.new(512).digest(int_sum_input)
      s_factor = 16 + intermediate_0[0].ord
      s_bytes_input = ""
      s_factor.times do
        s_bytes_input << salt
      end
      p_bytes_input = ""
      p_length.times do
        p_bytes_input << pass
      end
      s_bytes = Digest::SHA2.new(512).digest(s_bytes_input)[0..(s_length - 1)]
      p_bytes = Digest::SHA2.new(512).digest(p_bytes_input)[0..(p_length - 1)]
      [s_bytes, p_bytes, intermediate_0]
    end

    def round(i, s, p, intermediate)
      hash_input = ""
      hash_input << intermediate if ((i % 2) == 0)
      hash_input << p if ((i % 2) == 1)
      hash_input << s if ((i % 3) != 0)
      hash_input << p if ((i % 7) != 0)
      hash_input << p if ((i % 2) == 0)
      hash_input << intermediate if ((i % 2) == 1)
      (Digest::SHA2.new(512).digest(hash_input))
    end

    # Don't ask me how or why this works.  I don't actually understand it.
    # All I know is that it gives the right answer according to the tests cases.
    # The original instructions on how to implement this algorithm are kind of hairy and not well explained, you're welcome to injure yourself trying to understand them here:
    #   http://www.akkadia.org/drepper/SHA-crypt.txt
    # Follow item #22 on, and be amazed at the pain.
    def finalize_block(hash_val)
      # Remember, groups AND bytes are LSB ordered
=begin
      index_hash = [
        0, 21, 42,
        22, 43, 1,
        44, 2, 23,
        3, 24, 45,
        25, 46, 4,
        47, 5, 26,
        6, 27, 48,
        28, 49, 7,
        50, 8, 29,
        9, 30, 51,
        31, 52, 10,
        53, 11, 32,
        12, 33, 54,
        34, 55, 13,
        56, 14, 35,
        15, 36, 57,
        37, 58, 16,
        59, 17, 38,
        18, 39, 60,
        40, 61, 19,
        62, 20, 41,
        63
      ]
=end
      index_hash = [63, 62, 20, 41, 40, 61, 19, 18, 39, 60, 59, 17, 38, 37, 58, 16, 15, 36, 57, 56, 14, 35, 34, 55, 13, 12, 33, 54, 53, 11, 32, 31, 52, 10, 9, 30, 51, 50, 8, 29, 28, 49, 7, 6, 27, 48, 47, 5, 26, 25, 46, 4, 3, 24, 45, 44, 2, 23, 22, 43, 1, 0, 21, 42].reverse

      reordered_hash = (0..63).to_a.map { |i| [hash_val.getbyte(index_hash[i])].pack("*C") }
      bytes_array = []
      reordered_hash.each_slice(3) { |b_slice|
        bytes_array << b_slice
      }
      three_byte_sets = bytes_array.first(21)
      last_byte = bytes_array.last
      (three_byte_sets.map { |tbs| encode_triple_bytes(tbs) }.join + encode_last_byte(last_byte))
    end

    # BITS COME IN LSB!  Swap them!
    def six_bits_to_b64(bits)
      b64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      b64[bits.reverse.to_i(2)]
    end

    def encode_last_byte(byte)
      two_bit_groups = byte.first.unpack("b*").join.scan(/.{1,6}/)
      full_6_bits = two_bit_groups.first
      last_char = two_bit_groups.last + "0000"
      [six_bits_to_b64(full_6_bits), six_bits_to_b64(last_char)].join
    end

    def encode_triple_bytes(bytes)
      bytes.map { |e| e.unpack("b*") }.join.scan(/.{1,6}/).map {|v| six_bits_to_b64(v) }.join
    end

    def run(salt_val, pass_val)
      salt_trunc = salt_val[0..15]
      pass_trunc = pass_val
      sb, pb, i0 = init_hash(salt_trunc.force_encoding(Encoding::UTF_8), pass_trunc.force_encoding(Encoding::UTF_8))

      hash_val = (0..4999).to_a.inject(i0) do |acc, i|
        val = round(i, sb, pb, acc)
      end

      "$6$" + salt_trunc  + "$" + finalize_block(hash_val)
    end

    def encrypt(plain)
      run(generate_salt, plain)
    end

    def generate_salt
      SecureRandom.hex(8)
    end

  end
end
