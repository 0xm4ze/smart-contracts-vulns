# Solana-Specific Security Checklist

This checklist focuses on security considerations specific to Rust smart contracts deployed on the Solana blockchain.

## Account Validation

### 1. Account Ownership

- [ ] Verify that all accounts have their `owner` checked explicitly
- [ ] Ensure the `owner` check is performed before any account data is used
- [ ] Check that system-owned accounts are not modified by the program

```rust
// Example of proper ownership check
if account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

### 2. Program Derived Addresses (PDAs)

- [ ] Verify that all PDAs are derived with the correct seeds
- [ ] Ensure bump seeds are properly validated
- [ ] Check that PDAs are used appropriately for cross-program authority

```rust
// Example of proper PDA validation
let (expected_pda, bump_seed) = Pubkey::find_program_address(
    &[b"token", authority.key.as_ref()],
    program_id
);

if expected_pda != *pda.key {
    return Err(ProgramError::InvalidAccountData);
}
```

### 3. Account Data Validation

- [ ] Verify that account data size is validated before deserialization
- [ ] Check for proper initialization of account data
- [ ] Ensure account discriminators are validated

```rust
// Example of proper data size validation
if account.data_len() < std::mem::size_of::<AccountState>() {
    return Err(ProgramError::AccountDataTooSmall);
}
```

## Cross-Program Invocation (CPI) Security

### 1. CPI Privilege Validation

- [ ] Verify that CPIs are made with appropriate privileges
- [ ] Check for proper handling of signed vs unsigned CPIs
- [ ] Ensure proper PDA seeds are used for `invoke_signed`

```rust
// Example of proper CPI with invoke_signed
invoke_signed(
    &instruction,
    accounts,
    &[&[b"vault", authority.key.as_ref(), &[bump_seed]]],
)?;
```

### 2. Reentrancy Protection

- [ ] Check for reentrancy locks on sensitive operations
- [ ] Verify that state changes happen before external calls
- [ ] Ensure the checks-effects-interactions pattern is followed

```rust
// Example of checks-effects-interactions pattern
// 1. Check
if pool.token_a_balance < amount {
    return Err(ProgramError::InsufficientFunds);
}

// 2. Effect (update internal state first)
pool.token_a_balance -= amount;

// 3. Interaction (external call comes last)
token_transfer(...)?;
```

### 3. Instruction Data Validation

- [ ] Verify that all instruction data is properly validated
- [ ] Check for proper handling of variable-length data
- [ ] Ensure instruction identifiers are validated

```rust
// Example of proper instruction data validation
if instruction_data.len() < 9 {  // 1 byte for instruction identifier + 8 bytes for amount
    return Err(ProgramError::InvalidInstructionData);
}

let instruction = instruction_data[0];
let amount = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
```

## Compute Budget Considerations

### 1. Transaction Size

- [ ] Check for potential transaction size limitations
- [ ] Verify that operations can be completed within compute budget
- [ ] Ensure efficient data structures are used

### 2. Compute Unit Optimization

- [ ] Check for potential compute unit exhaustion
- [ ] Verify that loops have bounded iterations
- [ ] Ensure efficient algorithms are used

```rust
// Example of compute unit exhaustion vulnerability (unbounded loop)
// BAD:
for i in 0..accounts.len() {  // This could exhaust compute units if accounts is large
    // process each account
}

// GOOD:
if accounts.len() > MAX_ACCOUNTS {
    return Err(ProgramError::MaxAccountsExceeded);
}
for i in 0..accounts.len() {
    // process each account
}
```

## Solana-Specific Vulnerabilities

### 1. Account Data Reallocation

- [ ] Verify safe handling of account reallocation
- [ ] Check for proper rent exemption handling
- [ ] Ensure account data is zeroed properly after reallocation

### 2. Closing Accounts

- [ ] Verify that account closing transfers the lamports properly
- [ ] Check for proper handling of account data when closing
- [ ] Ensure closed accounts are not reused

### 3. Lamport Balance Management

- [ ] Verify proper handling of lamport balances
- [ ] Check for rent exemption considerations
- [ ] Ensure lamports are not lost when transferring

## Additional Resources

- [Solana Program Security Guidelines](https://docs.solana.com/developing/programming-model/security)
- [Anchor Framework Security Best Practices](https://book.anchor-lang.com/anchor_in_depth/security_considerations.html)
- [Solana Security Audit Checklist](https://github.com/slowmist/solana-smart-contract-security-checklist)
