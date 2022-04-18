// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
// Licensed under the Apache License, Version 2.0 (the "License");

#include "state/encryptor.h"

#include <doctest/doctest.h>

namespace State
{
static const std::string contents_ = "hello world";
std::vector<uint8_t> plain(contents_.begin(), contents_.end());

TEST_CASE("serialised state encryption")
{
    auto owner1_kp = crypto::make_key_pair(crypto::CurveID::SECP256K1);
    auto owner2_kp = crypto::make_key_pair(crypto::CurveID::SECP256K1);
    std::vector<uint8_t> cipher;
    {
        auto encryptor = make_encryptor(owner1_kp, owner2_kp->public_key_raw());
        encryptor->encrypt(plain, cipher);
    }
    std::vector<uint8_t> plain_;
    auto encryptor = make_encryptor(owner2_kp, owner1_kp->public_key_raw());
    CHECK(encryptor->decrypt(cipher, plain_));
    CHECK(plain_ == plain);
}

} // namespace State