require 'spec_helper'

describe Rypt::Sha512 do
  subject { Rypt::Sha512.new } 

  it "should output the proper hash in the pathological case" do
    expect(subject.run("salted", "password")).to eq "$6$salted$/zTQ7CjZH8wweVbQm04I7lDdky41N0fNJcioYrtxgIiY1qrrWcbdx8FcueRl/oJVk0UGKVeABtVvQBSbSpS6v0"
  end
end
