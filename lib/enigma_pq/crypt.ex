defmodule EnigmaPq.Crypt do
  @moduledoc """
  Post-Quantum Cryptography functions using ML-KEM1024 and ML-DSA87.
  Provides the same API as Enigma.Crypt but with quantum-resistant algorithms.
  """

  alias Enigma.Cipher

  @kem_algorithm :mlkem1024
  @dsa_algorithm :mldsa87

  @doc """
  Generate ML-KEM1024 key pair for key encapsulation.
  Returns {private_key, public_key} tuple.
  """
  def generate_keys do
    {public, private} = :crypto.generate_key(@kem_algorithm, [])
    {private, public}
  end

  @doc """
  Generate ML-DSA87 signing key pair.
  Returns {private_key, public_key} tuple.
  """
  def generate_signing_keys do
    {public, private} = :crypto.generate_key(@dsa_algorithm, [])
    {private, public}
  end

  @doc """
  Compute shared secret using ML-KEM1024.

  Note: ML-KEM uses a different paradigm than ECDH. The result includes both
  the shared secret and a ciphertext that must be transmitted to the other party.

  Returns {kem_ciphertext, shared_secret}.
  """
  def compute_secret(public) when is_binary(public) do
    {secret, encap_secret} = :crypto.encapsulate_key(@kem_algorithm, public)
    {encap_secret, secret}
  end

  def compute_secret(_private, public) when is_binary(public) do
    compute_secret(public)
  end

  @doc """
  Decapsulate the shared secret using ML-KEM1024.
  The recipient uses their private key to extract the shared secret from ciphertext.
  Returns the shared_secret.
  """
  def decapsulate_secret(private, ciphertext) when is_binary(private) and is_binary(ciphertext) do
    :crypto.decapsulate_key(@kem_algorithm, private, ciphertext)
  end

  @doc """
  Extract public key from a combined key structure.

  For ML-KEM, we store keys as {private, public} tuples since they must be generated together.
  This function extracts the public key from such a structure.
  """
  def private_to_public({_private, public}), do: public
  def private_to_public(private) when is_binary(private) do
    raise ArgumentError, "ML-KEM requires key pairs to be generated together. Store as {private, public} tuple."
  end

  @doc """
  Generate a random 32-byte secret for symmetric encryption.
  """
  def generate_secret do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Encrypt data using ML-KEM1024 for key exchange and symmetric cipher.

  Note: Returns {encrypted_data, kem_ciphertext} tuple. The kem_ciphertext must be
  transmitted along with encrypted_data to allow decryption.
  """
  def encrypt(data, _private, public) do
    {secret, encap_secret} = :crypto.encapsulate_key(@kem_algorithm, public)
    encrypted_data = Cipher.cipher(data, secret)
    {encrypted_data, encap_secret}
  end

  @doc """
  Encrypt and sign data using ML-KEM1024 and ML-DSA87.

  The signing_private should be from generate_signing_keys/0.
  Returns {{encrypted_data, kem_ciphertext}, signature}.
  """
  def encrypt_and_sign(data, signing_private, recipient_public) do
    encrypted_tuple = encrypt(data, nil, recipient_public)
    signature = sign(data, signing_private)
    {encrypted_tuple, signature}
  end

  @doc """
  Encrypt and bi-sign data (sign both plaintext and ciphertext).

  src_signing_private: sender's signing key
  dst_private: destination's KEM private key (to get public for encryption)

  Returns {{encrypted_data, kem_ciphertext}, data_signature, encrypted_data_signature}.
  """
  def encrypt_and_bisign(data, src_signing_private, dst_private) do
    dst_public = private_to_public(dst_private)
    {{encrypted_data, kem_ciphertext}, data_signature} =
      encrypt_and_sign(data, src_signing_private, dst_public)

    # For bi-signing, we need destination's signing key
    # This is a design choice - in PQ world, we separate KEM and signing keys
    # We'll need to pass the destination's signing private key separately
    raise ArgumentError, "encrypt_and_bisign requires destination's signing private key. Use encrypt_and_bisign/4"
  end

  def encrypt_and_bisign(data, src_signing_private, dst_kem_private, dst_signing_private) do
    dst_public = private_to_public(dst_kem_private)
    {{encrypted_data, kem_ciphertext}, data_signature} =
      encrypt_and_sign(data, src_signing_private, dst_public)

    encrypted_data_signature = sign(encrypted_data, dst_signing_private)

    {{encrypted_data, kem_ciphertext}, data_signature, encrypted_data_signature}
  end

  @doc """
  Decrypt data using ML-KEM1024.

  Takes {encrypted_data, kem_ciphertext} tuple and decrypts using private key.
  The public parameter is ignored (kept for API compatibility).
  """
  def decrypt({encrypted_data, encap_secret}, private, _public) do
    shared_secret = :crypto.decapsulate_key(@kem_algorithm, private, encap_secret)
    Cipher.decipher(encrypted_data, shared_secret)
  end

  @doc """
  Decrypt and verify signed data.

  Returns {:ok, decrypted_data} if signature is valid, :error otherwise.
  """
  def decrypt_signed({{encrypted_data, kem_ciphertext}, signature}, private, _public, author_public) do
    decrypted = decrypt({encrypted_data, kem_ciphertext}, private, nil)

    if valid_sign?(signature, decrypted, author_public),
      do: {:ok, decrypted},
      else: :error
  end

  @doc """
  Decrypt and verify bi-signed data.

  Returns {:ok, decrypted_data} if both signatures are valid, :error_out_sign or :error otherwise.
  """
  def decrypt_bisigned(
        {{encrypted_data, kem_ciphertext}, data_signature, encrypted_data_signature},
        private,
        author_public
      ) do
    # Verify the encrypted data signature first (using our own signing public key)
    # We need to derive our signing public from our signing private
    # This requires the signing private key to be passed
    raise ArgumentError, "decrypt_bisigned requires signing public key. Use decrypt_bisigned/4"
  end

  def decrypt_bisigned(
        {{encrypted_data, kem_ciphertext}, data_signature, encrypted_data_signature},
        private,
        signing_public,
        author_public
      ) do
    if valid_sign?(encrypted_data_signature, encrypted_data, signing_public) do
      decrypt_signed({{encrypted_data, kem_ciphertext}, data_signature}, private, nil, author_public)
    else
      :error_out_sign
    end
  end

  @doc """
  Sign data using ML-DSA87.
  Returns the signature.
  """
  def sign(data, private) do
    :crypto.sign(@dsa_algorithm, :none, data, private)
  end

  @doc """
  Verify signature using ML-DSA87.
  Returns true if signature is valid, false otherwise.
  """
  def valid_sign?(signature, data, public) do
    :crypto.verify(@dsa_algorithm, :none, data, signature, public)
  end
end
