// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
// Licensed under the Apache License, Version 2.0 (the "License");

#include "ethereum/encryptor.h"

#include "eEVM/util.h"

#include <doctest/doctest.h>

namespace Ethereum
{

TEST_CASE("serialised state encryption")
{
    uint256_t val = 100;
    auto key = crypto::create_entropy()->random(32);
    auto encryptor = StateEncryptor::make_encryptor(key);
    std::vector<uint8_t> plain(32);
    eevm::to_big_endian(val, plain.data());
    std::vector<uint8_t> cipher;
    {
        encryptor->encrypt(plain, cipher);
    }

    std::vector<uint8_t> plain_;
    CHECK(encryptor->decrypt(cipher, plain_));
    CHECK(plain_ == plain);
}

} // namespace State
