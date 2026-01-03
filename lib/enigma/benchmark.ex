defmodule Enigma.Benchmark do
  @moduledoc """
  Benchmark throughput of symmetric encryption algorithms.

  Compares:
  - Blowfish CFB64 (current Enigma implementation)
  - AES-256-GCM (recommended for modern ARM/x86 with hardware acceleration)
  - ChaCha20-Poly1305 (recommended for devices without AES hardware)

  ## Usage

      Enigma.Benchmark.run()
      Enigma.Benchmark.run(data_sizes: [1024, 65536, 1_048_576])
      Enigma.Benchmark.run(iterations: 1000)
  """

  @default_iterations 100
  @default_data_sizes [
    64,
    1024,
    16_384,
    65_536,
    262_144,
    1_048_576
  ]

  @doc """
  Run benchmarks for all symmetric ciphers.

  ## Options

  - `:iterations` - Number of iterations per test (default: #{@default_iterations})
  - `:data_sizes` - List of data sizes in bytes to test (default: various sizes up to 1MB)
  """
  def run(opts \\ []) do
    iterations = Keyword.get(opts, :iterations, @default_iterations)
    data_sizes = Keyword.get(opts, :data_sizes, @default_data_sizes)

    IO.puts("\n" <> String.duplicate("=", 70))
    IO.puts("Symmetric Cipher Throughput Benchmark")
    IO.puts(String.duplicate("=", 70))
    IO.puts("Iterations per test: #{iterations}")
    IO.puts("Platform: #{:erlang.system_info(:system_architecture)}")
    IO.puts("OTP version: #{:erlang.system_info(:otp_release)}")
    IO.puts(String.duplicate("-", 70))

    results =
      for size <- data_sizes do
        data = :crypto.strong_rand_bytes(size)
        size_label = format_size(size)

        IO.puts("\nData size: #{size_label}")
        IO.puts(String.duplicate("-", 50))

        blowfish_result = benchmark_blowfish(data, iterations)
        aes_gcm_result = benchmark_aes_gcm(data, iterations)
        chacha_result = benchmark_chacha20(data, iterations)

        print_result("Blowfish CFB64", blowfish_result, size)
        print_result("AES-256-GCM", aes_gcm_result, size)
        print_result("ChaCha20-Poly1305", chacha_result, size)

        %{
          size: size,
          blowfish: blowfish_result,
          aes_gcm: aes_gcm_result,
          chacha: chacha_result
        }
      end

    print_summary(results)
    results
  end

  @doc """
  Quick benchmark with a single data size.
  """
  def quick(data_size \\ 65_536, iterations \\ 100) do
    run(data_sizes: [data_size], iterations: iterations)
  end

  def chacha_vector_test() do
    key = 0..31 |> Enum.to_list() |> :binary.list_to_bin()
    nonce = 0..11 |> Enum.to_list() |> :binary.list_to_bin()
    aad = <<1, 2, 3, 4>>
    pt = "Hello, PQ!"

    {ct, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, pt, aad, true)

    IO.puts("ChaCha20-Poly1305 Vector Test (compare with browser Noble)")
    IO.puts("key=" <> Base.encode16(key, case: :lower))
    IO.puts("nonce=" <> Base.encode16(nonce, case: :lower))
    IO.puts("aad=" <> Base.encode16(aad, case: :lower))
    IO.puts("pt=" <> Base.encode16(pt, case: :lower))
    IO.puts("ct=" <> Base.encode16(ct, case: :lower))
    IO.puts("tag=" <> Base.encode16(tag, case: :lower))
    IO.puts("ct_tag=" <> Base.encode16(ct <> tag, case: :lower))

    %{key: key, nonce: nonce, aad: aad, pt: pt, ct: ct, tag: tag}
  end

  # Blowfish CFB64 - current Enigma implementation
  defp benchmark_blowfish(data, iterations) do
    # Blowfish uses 8-byte IV, 16-byte key
    key = :crypto.strong_rand_bytes(16)
    iv = :crypto.strong_rand_bytes(8)

    {encrypt_time, ciphertext} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time(:blowfish_cfb64, key, iv, data, true)
        end)
      end)

    {decrypt_time, _} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time(:blowfish_cfb64, key, iv, ciphertext, false)
        end)
      end)

    %{
      encrypt_us: encrypt_time,
      decrypt_us: decrypt_time,
      iterations: iterations
    }
  end

  # AES-256-GCM - AEAD, hardware accelerated on modern CPUs
  defp benchmark_aes_gcm(data, iterations) do
    # AES-256 uses 32-byte key, 12-byte IV for GCM
    key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)
    aad = <<>>

    {encrypt_time, {ciphertext, tag}} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, true)
        end)
      end)

    {decrypt_time, _} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false)
        end)
      end)

    %{
      encrypt_us: encrypt_time,
      decrypt_us: decrypt_time,
      iterations: iterations
    }
  end

  # ChaCha20-Poly1305 - AEAD, fast in software
  defp benchmark_chacha20(data, iterations) do
    # ChaCha20 uses 32-byte key, 12-byte nonce
    key = :crypto.strong_rand_bytes(32)
    nonce = :crypto.strong_rand_bytes(12)
    aad = <<>>

    {encrypt_time, {ciphertext, tag}} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, data, aad, true)
        end)
      end)

    {decrypt_time, _} =
      :timer.tc(fn ->
        Enum.reduce(1..iterations, nil, fn _, _ ->
          :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ciphertext, aad, tag, false)
        end)
      end)

    %{
      encrypt_us: encrypt_time,
      decrypt_us: decrypt_time,
      iterations: iterations
    }
  end

  defp print_result(name, result, data_size) do
    total_bytes = data_size * result.iterations
    encrypt_throughput = calculate_throughput(total_bytes, result.encrypt_us)
    decrypt_throughput = calculate_throughput(total_bytes, result.decrypt_us)
    avg_encrypt_us = result.encrypt_us / result.iterations
    avg_decrypt_us = result.decrypt_us / result.iterations

    IO.puts(
      "  #{String.pad_trailing(name, 20)} | " <>
        "Enc: #{format_throughput(encrypt_throughput)} " <>
        "(#{Float.round(avg_encrypt_us, 1)} µs/op) | " <>
        "Dec: #{format_throughput(decrypt_throughput)} " <>
        "(#{Float.round(avg_decrypt_us, 1)} µs/op)"
    )
  end

  defp print_summary(results) do
    IO.puts("\n" <> String.duplicate("=", 70))
    IO.puts("Summary (Throughput in MB/s at largest data size)")
    IO.puts(String.duplicate("=", 70))

    largest = List.last(results)
    size = largest.size
    total_bytes = size * @default_iterations

    algorithms = [
      {"Blowfish CFB64", largest.blowfish},
      {"AES-256-GCM", largest.aes_gcm},
      {"ChaCha20-Poly1305", largest.chacha}
    ]

    throughputs =
      Enum.map(algorithms, fn {name, result} ->
        enc = calculate_throughput(total_bytes, result.encrypt_us)
        dec = calculate_throughput(total_bytes, result.decrypt_us)
        {name, enc, dec}
      end)

    max_enc = throughputs |> Enum.map(&elem(&1, 1)) |> Enum.max()
    max_dec = throughputs |> Enum.map(&elem(&1, 2)) |> Enum.max()

    IO.puts("")

    for {name, enc, dec} <- throughputs do
      enc_bar = String.duplicate("█", round(enc / max_enc * 30))
      dec_bar = String.duplicate("█", round(dec / max_dec * 30))

      IO.puts("#{String.pad_trailing(name, 20)}")
      IO.puts("  Encrypt: #{String.pad_leading(format_throughput(enc), 12)} #{enc_bar}")
      IO.puts("  Decrypt: #{String.pad_leading(format_throughput(dec), 12)} #{dec_bar}")
      IO.puts("")
    end

    # Winner announcement
    {fastest_enc_name, fastest_enc, _} = Enum.max_by(throughputs, &elem(&1, 1))
    {fastest_dec_name, _, fastest_dec} = Enum.max_by(throughputs, &elem(&1, 2))

    IO.puts(String.duplicate("-", 70))
    IO.puts("Fastest encryption: #{fastest_enc_name} (#{format_throughput(fastest_enc)})")
    IO.puts("Fastest decryption: #{fastest_dec_name} (#{format_throughput(fastest_dec)})")

    # Hardware acceleration hint
    IO.puts("")
    IO.puts("Note: If AES-256-GCM is fastest, your CPU has AES hardware acceleration.")
    IO.puts("      If ChaCha20 is fastest, consider using it for better performance.")
    IO.puts(String.duplicate("=", 70))
  end

  # Calculate throughput in bytes per second
  defp calculate_throughput(bytes, microseconds) when microseconds > 0 do
    bytes / (microseconds / 1_000_000)
  end

  defp calculate_throughput(_, _), do: 0.0

  # Format throughput as MB/s
  defp format_throughput(bytes_per_second) do
    mb_per_second = bytes_per_second / 1_048_576
    "#{Float.round(mb_per_second, 2)} MB/s"
  end

  # Format size with appropriate unit
  defp format_size(bytes) when bytes >= 1_048_576, do: "#{div(bytes, 1_048_576)} MB"
  defp format_size(bytes) when bytes >= 1024, do: "#{div(bytes, 1024)} KB"
  defp format_size(bytes), do: "#{bytes} B"
end
