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
