defmodule EnigmaPq.CryptTest do
  use ExUnit.Case
  doctest EnigmaPq.Crypt

  alias EnigmaPq.Crypt

  describe "key generation" do
    test "generate_keys/0 creates ML-KEM1024 key pair" do
      {private, public} = Crypt.generate_keys()

      assert is_binary(private)
      assert is_binary(public)
      assert byte_size(private) > 0
      assert byte_size(public) > 0

      assert byte_size(public) == 1568
      assert byte_size(private) == 3168
    end

    test "generate_signing_keys/0 creates ML-DSA87 key pair" do
      {private, public} = Crypt.generate_signing_keys()

      assert is_binary(private)
      assert is_binary(public)
      assert byte_size(private) > 0
      assert byte_size(public) > 0

      assert byte_size(public) == 2592
      assert byte_size(private) == 4896
    end

    test "generate_secret/0 creates 32-byte random secret" do
      secret = Crypt.generate_secret()

      assert is_binary(secret)
      assert byte_size(secret) == 32
    end
  end

  describe "encryption and decryption" do
    test "encrypt/3 and decrypt/3 work correctly" do
      {alice_private, alice_public} = Crypt.generate_keys()
      {bob_private, bob_public} = Crypt.generate_keys()

      data = "Hello, quantum-safe world!"

      # Alice encrypts for Bob
      encrypted = Crypt.encrypt(data, alice_private, bob_public)

      # Bob decrypts
      decrypted = Crypt.decrypt(encrypted, bob_private, alice_public)

      assert decrypted == data
    end

    test "encrypt/3 and decrypt/3 work with a large message" do
      {alice_private, alice_public} = Crypt.generate_keys()
      {bob_private, bob_public} = Crypt.generate_keys()

      data = :crypto.strong_rand_bytes(5 * 1024 * 1024)

      encrypted = Crypt.encrypt(data, alice_private, bob_public)
      decrypted = Crypt.decrypt(encrypted, bob_private, alice_public)

      assert decrypted == data
    end

    test "encrypt_and_sign/3 and decrypt_signed/4 work correctly" do
      {alice_kem_private, alice_kem_public} = Crypt.generate_keys()
      {alice_sign_private, alice_sign_public} = Crypt.generate_signing_keys()
      {bob_kem_private, bob_kem_public} = Crypt.generate_keys()

      data = "Signed message"

      # Alice encrypts and signs for Bob
      encrypted_signed = Crypt.encrypt_and_sign(data, alice_sign_private, bob_kem_public)

      # Bob decrypts and verifies
      result = Crypt.decrypt_signed(encrypted_signed, bob_kem_private, bob_kem_public, alice_sign_public)

      assert {:ok, data} == result
    end

    test "decrypt_signed/4 fails with invalid signature" do
      {alice_kem_private, alice_kem_public} = Crypt.generate_keys()
      {alice_sign_private, _alice_sign_public} = Crypt.generate_signing_keys()
      {bob_kem_private, bob_kem_public} = Crypt.generate_keys()
      {eve_sign_private, eve_sign_public} = Crypt.generate_signing_keys()

      data = "Signed message"

      # Alice encrypts and signs for Bob
      encrypted_signed = Crypt.encrypt_and_sign(data, alice_sign_private, bob_kem_public)

      # Bob tries to verify with Eve's public key (should fail)
      result = Crypt.decrypt_signed(encrypted_signed, bob_kem_private, bob_kem_public, eve_sign_public)

      assert :error == result
    end
  end

  describe "signing and verification" do
    test "sign/2 and valid_sign?/3 work correctly" do
      {private, public} = Crypt.generate_signing_keys()

      data = "Message to sign"
      signature = Crypt.sign(data, private)

      assert is_binary(signature)
      assert byte_size(signature) == 4627
      assert Crypt.valid_sign?(signature, data, public)
    end

    test "valid_sign?/3 rejects invalid signature" do
      {private, public} = Crypt.generate_signing_keys()

      data = "Original message"
      signature = Crypt.sign(data, private)

      tampered_data = "Tampered message"

      refute Crypt.valid_sign?(signature, tampered_data, public)
    end

    test "valid_sign?/3 rejects signature from different key" do
      {alice_private, _alice_public} = Crypt.generate_signing_keys()
      {_bob_private, bob_public} = Crypt.generate_signing_keys()

      data = "Message"
      signature = Crypt.sign(data, alice_private)

      refute Crypt.valid_sign?(signature, data, bob_public)
    end
  end

  describe "compute_secret and decapsulate_secret" do
    test "KEM encapsulation and decapsulation work" do
      {private, public} = Crypt.generate_keys()

      # Encapsulate
      {kem_ciphertext, shared_secret1} = Crypt.compute_secret(public)

      # Decapsulate
      shared_secret2 = Crypt.decapsulate_secret(private, kem_ciphertext)

      assert shared_secret1 == shared_secret2
      assert byte_size(shared_secret1) == 32
    end
  end

  describe "private_to_public" do
    test "extracts public key from tuple" do
      {private, public} = Crypt.generate_keys()

      extracted_public = Crypt.private_to_public({private, public})

      assert extracted_public == public
    end

    test "raises error for binary private key" do
      {private, _public} = Crypt.generate_keys()

      assert_raise ArgumentError, fn ->
        Crypt.private_to_public(private)
      end
    end
  end
end
