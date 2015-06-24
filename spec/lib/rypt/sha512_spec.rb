require 'spec_helper'

describe Rypt::Sha512 do
  subject { Rypt::Sha512.new } 

  it "should output the proper hash for the lowercase alphabet as both salt and password" do
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    expect(subject.run(alphabet, alphabet)).to eq "$6$abcdefghijklmnop$P.j6BSBkeOn6x4GLifpzcWHhNy94zhEyNXRWORB2ZQ0KunTjHlcWXpMuURzF8LXKbhutOZD4VUcOWbyA2rzej0"
  end

  it "should output the proper hash for salt saltstring and password \"Hello world!\"" do
    expect(subject.run("saltstring", "Hello world!")).to eq "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
  end

  it "should output the proper hash for salt barsnafu and password text" do
    expect(subject.run("barsnafu", "text")).to eq "$6$barsnafu$X.eSLkBHE/5J7fjjFxoftFbJ.1twts3xXRgO.tyQXepSmLwfYfCqM/zzwW9/luNZqqF1IjAHRHCTm3hNI.Egl."
  end

  it "should output the proper hash in the pathological case" do
    expect(subject.run("salted", "password")).to eq "$6$salted$/zTQ7CjZH8wweVbQm04I7lDdky41N0fNJcioYrtxgIiY1qrrWcbdx8FcueRl/oJVk0UGKVeABtVvQBSbSpS6v0"
  end
end

shared_examples "matches encrypted sha512" do |encrypted_pass, pass|
  it "should equate \"#{encrypted_pass}\" with \"#{pass}\"" do
    expect(Rypt::Sha512.compare(encrypted_pass, pass)).to eq true
  end
end

describe Rypt::Sha512, "given a pre-encrypted value to compare with a password" do
  include_examples "matches encrypted sha512", "$6$salted$/zTQ7CjZH8wweVbQm04I7lDdky41N0fNJcioYrtxgIiY1qrrWcbdx8FcueRl/oJVk0UGKVeABtVvQBSbSpS6v0", "password"
end

describe Rypt::Sha512, "asked to generate a salt" do
  let(:secure_random_salt) { "salt from securerandom" }

  it "should provide a salt 16 characters long" do
    expect(subject.generate_salt.length).to eq 16
  end

  it "should obtain the salt from SecureRandom" do
    allow(SecureRandom).to receive(:hex).with(8).and_return(secure_random_salt)
    expect(subject.generate_salt).to eq secure_random_salt
  end
end

describe Rypt::Sha512, "given only a plaintext value" do
  let(:plaintext) { "some plain text" }

  describe"should produce an encrypted value" do
    let(:ciphertext) { Rypt::Sha512.encrypt(plaintext) }

    specify "which is not nil" do
      expect(ciphertext).not_to eq nil
    end

    specify "which is different from the plaintext" do
      expect(ciphertext).not_to eq plaintext
    end

    specify "which contains a 16-char salt" do
      salt = ciphertext.split("$")[2]
      expect(salt.length).to eq 16
    end

    specify "which contains the encrypted hash" do
      hash = ciphertext.split("$")[3]
      expect(hash.length).to eq 86
    end
  end
end
