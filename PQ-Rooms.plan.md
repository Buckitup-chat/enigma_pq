# Post-Quantum Rooms Architecture Plan

## Overview

This document outlines the migration from ECC-based room cryptography to post-quantum (PQ) cryptography using ML-KEM-1024 and ML-DSA-87, while adding advanced permission modes and maintaining the decentralized, USB-sync-first architecture.

## Current System (ECC)

The existing system uses a shared ECC keypair as a room access token:
- **Single room private key** shared among all members
- Possession of room private key = read all messages
- Messages are **bi-signed**: encrypted with room key, then signed with both user key and room key
- Server validates room signature to prove sender has room access
- No granular permissions (everyone can read/write)
- No proper revocation (banned users keep the private key)

## Design Goals

1. **Post-quantum security**: Use ML-KEM-1024 for key exchange, ML-DSA-87 for signatures
2. **Proper revocation**: Banned users cannot read new messages
3. **Efficient messaging**: Minimize per-message overhead (no KEM per message)
4. **Invite chain**: Social trust model where members can invite others without admin online
5. **Granular permissions**: Support write-only, read-pending, banning
6. **USB-sync friendly**: Deterministic merge of divergent branches using hash DAG
7. **Cryptography as truth**: No trusted server, all permissions enforced cryptographically

## Core Concepts

### 1. Epoch-Based Key Rotation

Instead of per-message KEM or a single shared key, we use **symmetric keys per recipient set**:

- **Epoch**: A symmetric `content_key` valid for a specific set of members
- **Key wrapping**: When membership changes, wrap the content key to each valid member using ML-KEM
- **On invite**: Reuse same `content_key`, wrap to expanded member set (one-time KEM overhead)
- **On revoke**: Generate NEW `content_key`, wrap to remaining members (revoked user has old key)
- **Messages**: Include `epoch` number, use symmetric encryption (fast, small)

**Benefits**:
- Message overhead: Just epoch number (4 bytes) + symmetric ciphertext
- Revocation works: New key generated, banned user can't decrypt
- Invite is efficient: Reuse key, just wrap to more people
- One-time KEM cost on membership changes, not every message

### 2. Invite Chain with Capability Delegation

Members can invite new users without admin being online:

- **InviteProof**: Cryptographic proof that user A invited user B
- **Capability delegation**: Members with `:invite` permission can grant access
- **Chain validation**: Server validates invite chain back to room creator
- **KeyRotation message**: When invite accepted, post message with new epoch keys

**Flow**:
1. Alice (member with `:invite` permission) creates InviteProof for Bob
2. InviteProof includes Bob's KEM/DSA pubkeys, permissions, signed by Alice's DSA key
3. Bob accepts by signing InviteProof with his DSA key
4. Server validates: Alice has `:invite` permission → Alice's signature valid → Bob's acceptance valid
5. New epoch created with content_key wrapped to all current members + Bob
6. KeyRotation message posted to room with new wrapped keys

### 3. Hash DAG for USB Sync

Messages form a Directed Acyclic Graph for deterministic merge:

- **Message hash**: Content-based identifier (hash of encrypted content + author + signature)
- **Parent hash**: Reference to previous message(s) in the conversation
- **Topological sort**: On merge, rebuild consistent ordering from DAG
- **Index reassignment**: Server-assigned indices are branch-local, hash is global identity

**Merge strategy**:
1. Collect all messages from both branches
2. Deduplicate by message hash
3. Topological sort using parent_hash references
4. Reassign indices sequentially
5. Validate each message against epoch membership at its index

### 4. Permission Modes

Each `InviteProof` specifies permissions:

- **`:read`**: Can decrypt messages (has wrapped content_key in epoch)
- **`:write`**: Can post messages (server checks permission)
- **`:invite`**: Can invite new members (capability delegation)

**Advanced modes** (future):
- **Write-only (blind submission)**: `:write` without `:read` - user posts encrypted to room, can't decrypt others
- **Read-pending**: User has `:read` but messages encrypted with separate approval_key until approved
- **Banning**: Remove from valid_members, generate new content_key

## Data Structures

### Room

```elixir
defmodule Room do
  defstruct [
    :pub_key,              # Room identifier (hash of creator + salt)
    :current_epoch,        # Active epoch number (e.g., 5)
    :epochs,               # %{epoch_id => EpochKey}
    :members,              # %{kem_pubkey => InviteProof}
    :creator_kem_pubkey,   # Room creator (has all permissions)
    :messages              # [Message, ...]
  ]
end
```

### EpochKey

```elixir
defmodule Room.EpochKey do
  @moduledoc """
  Represents a symmetric content key valid for a specific set of members.
  Created when membership changes (invite or revocation).
  """
  defstruct [
    :epoch_id,             # 1, 2, 3... (auto-increment)
    :content_key,          # 32-byte symmetric key for encrypting messages
    :valid_members,        # [kem_pubkey, ...] who can decrypt this epoch
    :wrapped_keys,         # %{kem_pubkey => {kem_ct, wrapped_content_key}}
    :created_at_index,     # Message index where this epoch started
    :reason                # :create | {:invite, pubkey} | {:revoke, pubkey}
  ]
end
```

**Key insights**:
- `content_key` is the actual symmetric key used to encrypt messages
- `wrapped_keys` contains the content_key encrypted to each member using ML-KEM
- On invite: Same `content_key`, new `wrapped_keys` with additional member
- On revoke: New `content_key`, new `wrapped_keys` excluding revoked member

### InviteProof

```elixir
defmodule Room.InviteProof do
  @moduledoc """
  Cryptographic proof that a user was invited to the room.
  Forms a chain of trust back to the room creator.
  """
  defstruct [
    :invitee_kem_pubkey,       # ML-KEM public key of invited user
    :invitee_dsa_pubkey,       # ML-DSA public key of invited user
    :permissions,              # [:read, :write, :invite]
    :inviter_kem_pubkey,       # Who invited them
    :inviter_dsa_pubkey,       # Inviter's signing key
    :invite_index,             # Message index where invite was posted
    :invite_signature,         # ML-DSA sig by inviter over invite data
    :acceptance_signature      # ML-DSA sig by invitee (proves possession of private key)
  ]
end
```

### KeyRotation

```elixir
defmodule Room.KeyRotation do
  @moduledoc """
  Special message posted when membership changes.
  Contains wrapped content keys for the new epoch.
  """
  defstruct [
    :epoch_id,                 # New epoch number
    :valid_members,            # [kem_pubkey, ...] in this epoch
    :wrapped_keys,             # %{kem_pubkey => {kem_ct, wrapped}}
    :reason,                   # {:invite, pubkey} | {:revoke, pubkey}
    :created_at_index,         # Index of this KeyRotation message
    :signature                 # ML-DSA sig by authorized member
  ]
end
```

### Message

```elixir
defmodule Room.Message do
  @moduledoc """
  Encrypted room message. Uses symmetric encryption with epoch's content_key.
  """
  defstruct [
    :encrypted,                # Symmetric ciphertext (Blowfish CFB64)
    :epoch,                    # Which epoch's content_key was used
    :author_kem_pubkey,        # Message author (for member lookup)
    :author_dsa_pubkey,        # For signature verification
    :signature,                # ML-DSA sig of plaintext by author
    :index,                    # Server-assigned index (branch-local)
    :hash,                     # Hash of (encrypted || epoch || author || sig)
    :parent_hash               # Hash of previous message (for DAG)
  ]
end
```

## Key Flows

### Flow 1: Room Creation

1. Admin generates ML-KEM and ML-DSA keypairs
2. Generate initial `content_key` (32 random bytes)
3. Wrap `content_key` to admin using ML-KEM:
   - `{kem_ct, shared_secret} = compute_secret(admin_kem_pubkey)`
   - `wrapped = cipher(content_key, shared_secret)`
4. Create epoch 1 with admin as sole member
5. Room is ready for messages

**Result**: Epoch 1 with content_key wrapped to admin only

### Flow 2: Invite New Member

1. Alice (member with `:invite` permission) wants to invite Bob
2. Alice creates `InviteProof`:
   - Bob's KEM/DSA pubkeys
   - Permissions to grant (e.g., `[:read, :write]`)
   - Alice signs with her DSA private key
3. Bob accepts by signing InviteProof with his DSA private key
4. Server validates invite chain:
   - Alice is in current epoch's `valid_members`
   - Alice has `:invite` permission
   - Signatures are valid
5. Create new epoch:
   - **Reuse same content_key** (efficiency!)
   - `valid_members` = old list + Bob
   - Wrap content_key to ALL members (including Bob)
6. Post `KeyRotation` message to room
7. Bob can now decrypt all messages in new epoch

**Result**: New epoch with same key wrapped to expanded member set

### Flow 3: Revoke Member (Ban)

1. Admin wants to ban Carol
2. Admin creates revocation:
   - Specifies Carol's KEM pubkey
   - Signs with admin DSA key
3. Server validates: Admin has authority
4. Create new epoch:
   - **Generate NEW content_key** (Carol has old one!)
   - `valid_members` = old list - Carol
   - Wrap new content_key to remaining members only
5. Post `KeyRotation` message to room
6. Carol cannot decrypt messages in new epoch (doesn't have new key)

**Result**: New epoch with new key, Carol excluded

### Flow 4: Post Message

1. Alice wants to post message
2. Get current epoch's `content_key` from local room state
3. Sign plaintext with Alice's DSA private key
4. Encrypt plaintext with `content_key` (symmetric)
5. Create `Message`:
   - `encrypted` = ciphertext
   - `epoch` = current epoch number
   - `author_*` = Alice's pubkeys
   - `signature` = ML-DSA sig
   - `parent_hash` = hash of previous message
6. Compute message hash
7. Post to room

**Result**: Message encrypted with symmetric key, minimal overhead

### Flow 5: Decrypt Message

1. Bob receives message with `epoch: 5`
2. Lookup `room.epochs[5]`
3. Check if Bob is in `epoch.valid_members`
4. If yes, lookup `epoch.wrapped_keys[bob_kem_pubkey]`
5. Unwrap content_key:
   - `shared_secret = decapsulate_secret(bob_kem_private, kem_ct)`
   - `content_key = decipher(wrapped, shared_secret)`
6. Decrypt message: `plaintext = decipher(encrypted, content_key)`
7. Verify signature: `valid_sign?(signature, plaintext, author_dsa_pubkey)`

**Result**: Plaintext if Bob is authorized and signature valid, error otherwise

### Flow 6: USB Sync & Branch Merge

Two USB drives diverge and sync:

1. **Collect KeyRotation messages** from both branches
2. **Deduplicate** by epoch_id
3. **Sort by created_at_index** (deterministic)
4. **Replay rotations** in order to rebuild epoch history
5. **Collect all messages** from both branches
6. **Deduplicate** by message hash
7. **Topological sort** using `parent_hash` DAG
8. **Reassign indices** sequentially
9. **Validate** each message against epoch membership at its index
10. **Filter** invalid messages (author not in valid_members)

**Result**: Merged room state with consistent epoch history and message ordering

---

# Part 2: Implementation Plan

## TODO List

### Phase 1: Core Data Structures

- [ ] Create `lib/room/epoch_key.ex` module
- [ ] Create `lib/room/invite_proof.ex` module
- [ ] Create `lib/room/key_rotation.ex` module
- [ ] Create `lib/room/message.ex` module
- [ ] Create `lib/room.ex` main module

### Phase 2: Key Wrapping Primitives

- [ ] Implement `wrap_key_to(content_key, recipient_kem_pubkey)` using ML-KEM
- [ ] Implement `unwrap_key(kem_ct, wrapped, my_kem_private)` for decapsulation
- [ ] Add tests for wrap/unwrap round-trip

### Phase 3: Room Lifecycle

- [ ] Implement `Room.create(admin_identity)` - initial room setup
- [ ] Implement `Room.invite_member(room, invite_proof, current_index)` - add member
- [ ] Implement `Room.revoke_member(room, member_pubkey, revoker_identity, current_index)` - ban
- [ ] Add tests for create → invite → revoke flow

### Phase 4: Invite Chain Validation

- [ ] Implement `InviteProof.create(inviter, invitee, permissions)` - generate proof
- [ ] Implement `InviteProof.accept(proof, invitee_identity)` - sign acceptance
- [ ] Implement `InviteProof.validate(proof, room)` - check chain back to creator
- [ ] Add tests for multi-hop invite chains (Alice → Bob → Carol)

### Phase 5: Message Operations

- [ ] Implement `Message.create(content, room, author_identity, index)` - encrypt and sign
- [ ] Implement `Message.decrypt(message, room, my_identity)` - decrypt and verify
- [ ] Implement message hash computation (for DAG)
- [ ] Add tests for encrypt/decrypt with multiple epochs

### Phase 6: USB Sync & Merge

- [ ] Implement `Room.merge(room_a, room_b)` - DAG merge logic
- [ ] Implement `topological_sort(messages)` using parent_hash
- [ ] Implement epoch replay from KeyRotation messages
- [ ] Add tests for branch divergence scenarios

### Phase 7: Integration with Existing System

- [ ] Update `Chat.SignedParcel` to handle `Room.KeyRotation` messages
- [ ] Update `Chat.Rooms.RoomMessages` to use new epoch-based encryption
- [ ] Migrate `bisign` pattern to ML-DSA signatures
- [ ] Add migration path for existing ECC rooms

### Phase 8: Advanced Features

- [ ] Implement write-only mode (`:write` without `:read`)
- [ ] Implement read-pending mode (approval_key mechanism)
- [ ] Add permission checks to server validation
- [ ] Add tests for permission edge cases

## Implementation Code

### 1. Key Wrapping Primitives

```elixir
defmodule Room.KeyWrap do
  @moduledoc """
  Utilities for wrapping/unwrapping symmetric keys using ML-KEM.
  """

  alias EnigmaPq.Crypt
  alias Enigma.Cipher

  @doc """
  Wrap a symmetric content_key to a recipient using ML-KEM.

  Returns {kem_ciphertext, wrapped_content_key}.
  """
  def wrap_to(content_key, recipient_kem_pubkey) do
    # KEM encapsulation generates a shared secret
    {kem_ciphertext, shared_secret} = Crypt.compute_secret(recipient_kem_pubkey)

    # Encrypt content_key with the shared secret
    wrapped = Cipher.cipher(content_key, shared_secret)

    {kem_ciphertext, wrapped}
  end

  @doc """
  Unwrap a content_key using ML-KEM private key.

  Returns the content_key.
  """
  def unwrap(kem_ciphertext, wrapped_content_key, my_kem_private) do
    # Decapsulate to get shared secret
    shared_secret = Crypt.decapsulate_secret(my_kem_private, kem_ciphertext)

    # Decrypt content_key
    Cipher.decipher(wrapped_content_key, shared_secret)
  end

  @doc """
  Wrap content_key to multiple recipients.

  Returns %{kem_pubkey => {kem_ct, wrapped}}.
  """
  def wrap_to_many(content_key, recipient_kem_pubkeys) do
    Enum.map(recipient_kem_pubkeys, fn pubkey ->
      {pubkey, wrap_to(content_key, pubkey)}
    end)
    |> Map.new()
  end
end
```

### 2. Room Creation

```elixir
defmodule Room do
  defstruct [
    :pub_key,
    :current_epoch,
    :epochs,
    :members,
    :creator_kem_pubkey,
    :messages
  ]

  alias Room.{EpochKey, InviteProof, Message, KeyRotation, KeyWrap}
  alias EnigmaPq.Crypt

  @doc """
  Create a new room with admin as the sole initial member.
  """
  def create(admin_identity) do
    # Generate initial symmetric content key
    content_key = :crypto.strong_rand_bytes(32)

    # Wrap to admin using KEM
    admin_kem_pubkey = Crypt.private_to_public(admin_identity.kem_private)
    wrapped_keys = KeyWrap.wrap_to_many(content_key, [admin_kem_pubkey])

    # Create initial epoch
    epoch_key = %EpochKey{
      epoch_id: 1,
      content_key: content_key,
      valid_members: [admin_kem_pubkey],
      wrapped_keys: wrapped_keys,
      created_at_index: 0,
      reason: :create
    }

    # Generate room identifier
    room_pub_key = Enigma.Hash.hash([admin_kem_pubkey, :room, :crypto.strong_rand_bytes(16)])

    %Room{
      pub_key: room_pub_key,
      current_epoch: 1,
      epochs: %{1 => epoch_key},
      members: %{admin_kem_pubkey => :creator},
      creator_kem_pubkey: admin_kem_pubkey,
      messages: []
    }
  end
end
```

### 3. Invite Member

```elixir
defmodule Room do
  @doc """
  Process an invite and create a new epoch with expanded member set.

  Returns {updated_room, key_rotation_message}.
  """
  def invite_member(room, invite_proof, current_index) do
    # Validate invite chain
    unless InviteProof.validate(invite_proof, room) do
      raise ArgumentError, "Invalid invite proof"
    end

    # Get current epoch
    current_epoch = room.epochs[room.current_epoch]

    # REUSE same content_key (efficiency)
    content_key = current_epoch.content_key

    # Expand member set
    new_valid_members = current_epoch.valid_members ++ [invite_proof.invitee_kem_pubkey]

    # Wrap content_key to ALL members (including new one)
    new_wrapped_keys = KeyWrap.wrap_to_many(content_key, new_valid_members)

    # Create new epoch
    new_epoch_id = room.current_epoch + 1
    new_epoch = %EpochKey{
      epoch_id: new_epoch_id,
      content_key: content_key,  # SAME key
      valid_members: new_valid_members,
      wrapped_keys: new_wrapped_keys,
      created_at_index: current_index,
      reason: {:invite, invite_proof.invitee_kem_pubkey}
    }

    # Create KeyRotation message
    key_rotation = %KeyRotation{
      epoch_id: new_epoch_id,
      valid_members: new_valid_members,
      wrapped_keys: new_wrapped_keys,
      reason: {:invite, invite_proof.invitee_kem_pubkey},
      created_at_index: current_index,
      signature: sign_rotation(new_epoch, invite_proof.inviter_dsa_private)
    }

    # Update room state
    updated_room = %{room |
      current_epoch: new_epoch_id,
      epochs: Map.put(room.epochs, new_epoch_id, new_epoch),
      members: Map.put(room.members, invite_proof.invitee_kem_pubkey, invite_proof)
    }

    {updated_room, key_rotation}
  end

  defp sign_rotation(epoch_key, signer_dsa_private) do
    data = :erlang.term_to_binary({
      epoch_key.epoch_id,
      epoch_key.valid_members,
      epoch_key.reason
    })

    Crypt.sign(data, signer_dsa_private)
  end
end
```

### 4. Revoke Member

```elixir
defmodule Room do
  @doc """
  Revoke a member and create new epoch with fresh content_key.

  Returns {updated_room, key_rotation_message}.
  """
  def revoke_member(room, member_kem_pubkey, revoker_identity, current_index) do
    # Validate revoker has permission
    unless can_revoke?(revoker_identity, room) do
      raise ArgumentError, "Not authorized to revoke members"
    end

    # Get current epoch
    current_epoch = room.epochs[room.current_epoch]

    # Generate NEW content_key (banned user has old one!)
    new_content_key = :crypto.strong_rand_bytes(32)

    # Remove banned member
    new_valid_members = current_epoch.valid_members -- [member_kem_pubkey]

    # Wrap NEW key to remaining members only
    new_wrapped_keys = KeyWrap.wrap_to_many(new_content_key, new_valid_members)

    # Create new epoch
    new_epoch_id = room.current_epoch + 1
    new_epoch = %EpochKey{
      epoch_id: new_epoch_id,
      content_key: new_content_key,  # NEW key!
      valid_members: new_valid_members,
      wrapped_keys: new_wrapped_keys,
      created_at_index: current_index,
      reason: {:revoke, member_kem_pubkey}
    }

    # Create KeyRotation message
    revoker_kem_pubkey = Crypt.private_to_public(revoker_identity.kem_private)
    key_rotation = %KeyRotation{
      epoch_id: new_epoch_id,
      valid_members: new_valid_members,
      wrapped_keys: new_wrapped_keys,
      reason: {:revoke, member_kem_pubkey},
      created_at_index: current_index,
      signature: sign_rotation(new_epoch, revoker_identity.dsa_private)
    }

    # Update room state
    updated_room = %{room |
      current_epoch: new_epoch_id,
      epochs: Map.put(room.epochs, new_epoch_id, new_epoch),
      members: Map.delete(room.members, member_kem_pubkey)
    }

    {updated_room, key_rotation}
  end

  defp can_revoke?(identity, room) do
    kem_pubkey = Crypt.private_to_public(identity.kem_private)

    # Only creator can revoke (for now)
    kem_pubkey == room.creator_kem_pubkey
  end
end
```

### 5. Post Message

```elixir
defmodule Room.Message do
  defstruct [
    :encrypted,
    :epoch,
    :author_kem_pubkey,
    :author_dsa_pubkey,
    :signature,
    :index,
    :hash,
    :parent_hash
  ]

  alias EnigmaPq.Crypt
  alias Enigma.Cipher

  @doc """
  Create an encrypted message for the room.

  Uses the current epoch's content_key for symmetric encryption.
  """
  def create(content, room, author_identity, index) do
    # Get current epoch's content key
    epoch = room.current_epoch
    epoch_key = room.epochs[epoch]
    content_key = epoch_key.content_key

    # Extract author keys
    author_kem_pubkey = Crypt.private_to_public(author_identity.kem_private)
    author_dsa_pubkey = Crypt.private_to_public(author_identity.dsa_private)

    # Sign plaintext
    signature = Crypt.sign(content, author_identity.dsa_private)

    # Encrypt with symmetric key
    encrypted = Cipher.cipher(content, content_key)

    # Get previous message hash
    parent_hash = get_parent_hash(room, index)

    # Create message
    message = %__MODULE__{
      encrypted: encrypted,
      epoch: epoch,
      author_kem_pubkey: author_kem_pubkey,
      author_dsa_pubkey: author_dsa_pubkey,
      signature: signature,
      index: index,
      parent_hash: parent_hash
    }

    # Compute message hash
    %{message | hash: compute_hash(message)}
  end

  defp get_parent_hash(room, index) do
    case Enum.find(room.messages, fn msg -> msg.index == index - 1 end) do
      nil -> nil
      msg -> msg.hash
    end
  end

  defp compute_hash(message) do
    data = :erlang.term_to_binary({
      message.encrypted,
      message.epoch,
      message.author_kem_pubkey,
      message.author_dsa_pubkey,
      message.signature,
      message.parent_hash
    })

    Enigma.Hash.hash(data)
  end
end
```

### 6. Decrypt Message

```elixir
defmodule Room.Message do
  @doc """
  Decrypt a room message using recipient's identity.

  Returns {:ok, plaintext} or {:error, reason}.
  """
  def decrypt(message, room, my_identity) do
    # Get epoch key info
    epoch_key = room.epochs[message.epoch]

    unless epoch_key do
      return {:error, :unknown_epoch}
    end

    # Get my KEM public key
    my_kem_pubkey = Crypt.private_to_public(my_identity.kem_private)

    # Check if I'm authorized for this epoch
    case epoch_key.wrapped_keys[my_kem_pubkey] do
      nil ->
        {:error, :not_authorized}

      {kem_ciphertext, wrapped_content_key} ->
        # Unwrap content_key
        content_key = Room.KeyWrap.unwrap(
          kem_ciphertext,
          wrapped_content_key,
          my_identity.kem_private
        )

        # Decrypt message
        plaintext = Cipher.decipher(message.encrypted, content_key)

        # Verify signature
        if Crypt.valid_sign?(message.signature, plaintext, message.author_dsa_pubkey) do
          {:ok, plaintext}
        else
          {:error, :invalid_signature}
        end
    end
  end
end
```

### 7. Invite Chain Validation

```elixir
defmodule Room.InviteProof do
  defstruct [
    :invitee_kem_pubkey,
    :invitee_dsa_pubkey,
    :permissions,
    :inviter_kem_pubkey,
    :inviter_dsa_pubkey,
    :invite_index,
    :invite_signature,
    :acceptance_signature
  ]

  alias EnigmaPq.Crypt

  @doc """
  Create an invite proof for a new member.
  """
  def create(inviter_identity, invitee_pubkeys, permissions) do
    inviter_kem_pubkey = Crypt.private_to_public(inviter_identity.kem_private)
    inviter_dsa_pubkey = Crypt.private_to_public(inviter_identity.dsa_private)

    proof = %__MODULE__{
      invitee_kem_pubkey: invitee_pubkeys.kem,
      invitee_dsa_pubkey: invitee_pubkeys.dsa,
      permissions: permissions,
      inviter_kem_pubkey: inviter_kem_pubkey,
      inviter_dsa_pubkey: inviter_dsa_pubkey,
      invite_index: nil,  # Set when posted
      invite_signature: nil,
      acceptance_signature: nil
    }

    # Sign invite data
    invite_data = encode_invite_data(proof)
    invite_signature = Crypt.sign(invite_data, inviter_identity.dsa_private)

    %{proof | invite_signature: invite_signature}
  end

  @doc """
  Accept an invite by signing with invitee's key.
  """
  def accept(proof, invitee_identity) do
    acceptance_data = encode_acceptance_data(proof)
    acceptance_signature = Crypt.sign(acceptance_data, invitee_identity.dsa_private)

    %{proof | acceptance_signature: acceptance_signature}
  end

  @doc """
  Validate invite proof against room state.
  """
  def validate(proof, room) do
    with true <- validate_inviter_membership(proof, room),
         true <- validate_inviter_permissions(proof, room),
         true <- validate_invite_signature(proof),
         true <- validate_acceptance_signature(proof) do
      true
    else
      _ -> false
    end
  end

  defp validate_inviter_membership(proof, room) do
    current_epoch = room.epochs[room.current_epoch]
    proof.inviter_kem_pubkey in current_epoch.valid_members
  end

  defp validate_inviter_permissions(proof, room) do
    case room.members[proof.inviter_kem_pubkey] do
      :creator -> true
      %__MODULE__{permissions: perms} -> :invite in perms
      _ -> false
    end
  end

  defp validate_invite_signature(proof) do
    invite_data = encode_invite_data(proof)
    Crypt.valid_sign?(proof.invite_signature, invite_data, proof.inviter_dsa_pubkey)
  end

  defp validate_acceptance_signature(proof) do
    acceptance_data = encode_acceptance_data(proof)
    Crypt.valid_sign?(proof.acceptance_signature, acceptance_data, proof.invitee_dsa_pubkey)
  end

  defp encode_invite_data(proof) do
    :erlang.term_to_binary({
      proof.invitee_kem_pubkey,
      proof.invitee_dsa_pubkey,
      proof.permissions,
      proof.inviter_kem_pubkey
    })
  end

  defp encode_acceptance_data(proof) do
    :erlang.term_to_binary({
      proof.invitee_kem_pubkey,
      proof.invite_signature
    })
  end
end
```

### 8. USB Sync & Merge

```elixir
defmodule Room.Merge do
  @doc """
  Merge two divergent room branches.

  Uses KeyRotation messages to rebuild epoch history,
  then uses message DAG for deterministic ordering.
  """
  def merge(room_a, room_b) do
    # 1. Collect all KeyRotation messages from both branches
    all_rotations = collect_rotations(room_a, room_b)

    # 2. Replay rotations in order to rebuild consistent epoch history
    merged_epochs = replay_rotations(all_rotations, room_a)

    # 3. Collect and deduplicate messages by hash
    all_messages = (room_a.messages ++ room_b.messages)
      |> Enum.uniq_by(& &1.hash)

    # 4. Topological sort using parent_hash DAG
    sorted_messages = topological_sort(all_messages)

    # 5. Reassign indices
    reindexed_messages =
      sorted_messages
      |> Enum.with_index()
      |> Enum.map(fn {msg, new_index} -> %{msg | index: new_index} end)

    # 6. Validate messages against epoch membership
    valid_messages = filter_valid_messages(reindexed_messages, merged_epochs)

    # 7. Merge member lists (union)
    merged_members = Map.merge(room_a.members, room_b.members)

    %Room{
      pub_key: room_a.pub_key,
      current_epoch: merged_epochs.current_epoch,
      epochs: merged_epochs.epochs,
      members: merged_members,
      creator_kem_pubkey: room_a.creator_kem_pubkey,
      messages: valid_messages
    }
  end

  defp collect_rotations(room_a, room_b) do
    # Extract KeyRotation messages (typically stored separately or in message stream)
    # For now, rebuild from epochs
    epochs_a = Map.values(room_a.epochs)
    epochs_b = Map.values(room_b.epochs)

    (epochs_a ++ epochs_b)
    |> Enum.uniq_by(& &1.epoch_id)
    |> Enum.sort_by(& &1.created_at_index)
  end

  defp replay_rotations(rotations, initial_room) do
    Enum.reduce(rotations, %{epochs: %{}, current_epoch: 0}, fn rotation, acc ->
      %{
        epochs: Map.put(acc.epochs, rotation.epoch_id, rotation),
        current_epoch: max(acc.current_epoch, rotation.epoch_id)
      }
    end)
  end

  defp topological_sort(messages) do
    # Build dependency graph
    graph = build_graph(messages)

    # Kahn's algorithm for topological sort
    kahns_sort(graph)
  end

  defp build_graph(messages) do
    Enum.reduce(messages, %{nodes: %{}, edges: %{}}, fn msg, graph ->
      graph = put_in(graph, [:nodes, msg.hash], msg)

      if msg.parent_hash do
        edges = Map.get(graph.edges, msg.parent_hash, [])
        put_in(graph, [:edges, msg.parent_hash], [msg.hash | edges])
      else
        graph
      end
    end)
  end

  defp kahns_sort(graph) do
    # Find messages with no parents (roots)
    roots = Enum.filter(graph.nodes, fn {hash, msg} ->
      msg.parent_hash == nil or !Map.has_key?(graph.nodes, msg.parent_hash)
    end)

    # Sort recursively
    do_kahns_sort(roots, graph, [])
  end

  defp do_kahns_sort([], _graph, acc), do: Enum.reverse(acc)

  defp do_kahns_sort([{hash, msg} | rest], graph, acc) do
    # Add current message to result
    new_acc = [msg | acc]

    # Get children
    children = Map.get(graph.edges, hash, [])
      |> Enum.map(fn child_hash -> {child_hash, graph.nodes[child_hash]} end)

    # Continue with children + remaining roots
    do_kahns_sort(children ++ rest, graph, new_acc)
  end

  defp filter_valid_messages(messages, merged_epochs) do
    Enum.filter(messages, fn msg ->
      epoch = merged_epochs.epochs[msg.epoch]
      epoch && msg.author_kem_pubkey in epoch.valid_members
    end)
  end
end
```

## Testing Strategy

### Unit Tests

```elixir
defmodule RoomTest do
  use ExUnit.Case

  describe "room creation" do
    test "creates room with admin as sole member" do
      admin = generate_identity()
      room = Room.create(admin)

      assert room.current_epoch == 1
      assert map_size(room.epochs) == 1

      epoch1 = room.epochs[1]
      admin_pubkey = Crypt.private_to_public(admin.kem_private)

      assert epoch1.valid_members == [admin_pubkey]
      assert Map.has_key?(epoch1.wrapped_keys, admin_pubkey)
    end
  end

  describe "invite flow" do
    test "invites member with same content_key" do
      admin = generate_identity()
      bob = generate_identity()
      room = Room.create(admin)

      # Get original content_key
      original_key = room.epochs[1].content_key

      # Create and accept invite
      bob_pubkeys = %{
        kem: Crypt.private_to_public(bob.kem_private),
        dsa: Crypt.private_to_public(bob.dsa_private)
      }

      invite = InviteProof.create(admin, bob_pubkeys, [:read, :write])
      invite = InviteProof.accept(invite, bob)

      {room, _rotation} = Room.invite_member(room, invite, 1)

      # Should have new epoch
      assert room.current_epoch == 2

      # Should reuse same content_key
      assert room.epochs[2].content_key == original_key

      # Both members should be in valid_members
      admin_pubkey = Crypt.private_to_public(admin.kem_private)
      assert Enum.sort(room.epochs[2].valid_members) ==
             Enum.sort([admin_pubkey, bob_pubkeys.kem])
    end
  end

  describe "revocation" do
    test "generates new content_key on revoke" do
      admin = generate_identity()
      bob = generate_identity()
      room = Room.create(admin)

      # Invite Bob
      bob_pubkeys = %{
        kem: Crypt.private_to_public(bob.kem_private),
        dsa: Crypt.private_to_public(bob.dsa_private)
      }
      invite = InviteProof.create(admin, bob_pubkeys, [:read, :write])
      invite = InviteProof.accept(invite, bob)
      {room, _} = Room.invite_member(room, invite, 1)

      epoch2_key = room.epochs[2].content_key

      # Revoke Bob
      {room, _} = Room.revoke_member(room, bob_pubkeys.kem, admin, 2)

      # Should have new epoch
      assert room.current_epoch == 3

      # Should have NEW content_key
      refute room.epochs[3].content_key == epoch2_key

      # Bob should not be in valid_members
      refute bob_pubkeys.kem in room.epochs[3].valid_members
    end
  end

  describe "message encryption/decryption" do
    test "member can decrypt message in their epoch" do
      admin = generate_identity()
      room = Room.create(admin)

      content = "Hello, world!"
      message = Message.create(content, room, admin, 1)

      {:ok, decrypted} = Message.decrypt(message, room, admin)

      assert decrypted == content
    end

    test "revoked member cannot decrypt new messages" do
      admin = generate_identity()
      bob = generate_identity()
      room = Room.create(admin)

      # Invite Bob
      bob_pubkeys = %{
        kem: Crypt.private_to_public(bob.kem_private),
        dsa: Crypt.private_to_public(bob.dsa_private)
      }
      invite = InviteProof.create(admin, bob_pubkeys, [:read, :write])
      invite = InviteProof.accept(invite, bob)
      {room, _} = Room.invite_member(room, invite, 1)

      # Bob posts message (can decrypt)
      msg1 = Message.create("I'm in!", room, bob, 2)
      assert {:ok, _} = Message.decrypt(msg1, room, bob)

      # Revoke Bob
      {room, _} = Room.revoke_member(room, bob_pubkeys.kem, admin, 3)

      # Admin posts message in new epoch
      msg2 = Message.create("Secret!", room, admin, 4)

      # Admin can decrypt
      assert {:ok, "Secret!"} = Message.decrypt(msg2, room, admin)

      # Bob CANNOT decrypt (not in epoch 3)
      assert {:error, :not_authorized} = Message.decrypt(msg2, room, bob)
    end
  end
end

defp generate_identity do
  {kem_private, kem_public} = Crypt.generate_keys()
  {dsa_private, dsa_public} = Crypt.generate_signing_keys()

  %{
    kem_private: {kem_private, kem_public},
    dsa_private: {dsa_private, dsa_public}
  }
end
```

## Migration Path

### From ECC Rooms to PQ Rooms

1. **Dual-mode period**: Support both ECC and PQ rooms
2. **Migration message**: Admin posts special `RoomMigration` message
3. **Member acknowledgment**: Members post signed acceptance of migration
4. **Epoch 1 creation**: Once all members acknowledge, create PQ epoch 1
5. **Deprecate ECC**: After grace period, reject ECC-encrypted messages

### Backwards Compatibility

- Old clients can read archive (ECC messages) but not post new ones
- New clients understand both formats
- Server validates based on message type (ECC bisign vs PQ epoch)

---

## Security Considerations

1. **Forward Secrecy**: Each epoch rotation provides forward secrecy boundary
2. **Key Compromise**: If member's private key leaked, only their wrapped keys affected
3. **Revocation Timing**: Small window between revocation and message posting
4. **Replay Attacks**: Message hash + parent_hash prevent replays across branches
5. **Invite Chain DoS**: Rate limit invites, require stake/reputation for `:invite` permission

## Performance Analysis

### Message Overhead (per message)

- **Epoch number**: 4 bytes
- **Symmetric ciphertext**: ~plaintext length
- **ML-DSA signature**: 4627 bytes
- **KEM pubkey**: 1568 bytes
- **DSA pubkey**: 2592 bytes
- **Hash + parent_hash**: 64 bytes

**Total**: ~9 KB overhead per message (independent of room size!)

### KeyRotation Overhead (per membership change)

- **KEM wrapping**: 1568 bytes × member_count
- **50 members**: ~78 KB
- **100 members**: ~157 KB

**Amortized**: If room has 50 members and membership changes every 100 messages, overhead is ~780 bytes/message.

### Comparison to Per-Message KEM

- **Per-message KEM**: 1568 × 50 = 78 KB per message
- **Epoch approach**: 4 bytes per message + 78 KB per invite/revoke
- **Win**: ~100× smaller for stable membership

## Open Questions

1. **Partial epoch sync**: How to handle when USB drive only has some wrapped_keys?
2. **Epoch compaction**: Archive old epochs after all messages decrypted?
3. **Multi-admin governance**: Threshold signatures for revocations?
4. **Invite limits**: Should inviters have quota to prevent spam?
5. **Read receipts**: How to prove message decryption without leaking reads?

---

## References

- ML-KEM-1024 spec: NIST FIPS 203
- ML-DSA-87 spec: NIST FIPS 204
- Erlang `:crypto` module: https://www.erlang.org/doc/man/crypto.html
- Current ECC implementation: `chat/lib/chat/rooms/room_messages.ex`
