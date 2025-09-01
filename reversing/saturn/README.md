# Saturn [_snakeCTF 2025 Quals_]

**Category**: rev

## Description

We've discovered this ancient sheet of paper in the depths of the University of Udine's archives: it seems to be some mysterious flag-checking program. Rumors say it was last used in a computer security challenge in 1986.

## Solution

The challenge expands to:
```
«
# Test first part of the string "snake"
"Wrong Flag"
SWAP

1 5 FOR I 
  DUP I I SUB NUM DUP DUP 97 ≥ SWAP 122 ≤ AND NOT IF THEN ABORT END
  32 - CHR
  "SNAKE" I I SUB ≠ IF THEN ABORT END
  NEXT

# Test for CTF{
DUP 6 9 SUB "CTF{" ≠ IF THEN ABORT END

# Test } as last char
DUP DUP SIZE DUP SUB "}" ≠ IF THEN ABORT END

# Test string length >= 37
DUP SIZE 37 ≥ IF THEN ABORT END

# Crop the string to eliminate snake{}
DUP SIZE 1 - 10 SWAP SUB

# Split the string into two pieces
DUP DUP SIZE 13 SWAP SUB 'TFA' STO
DUP 1 12 SUB 'ENC' STO

# Check that TFA has no spaces
TFA " " POS 0 ≠ IF THEN ABORT END

# "Undefined Name"
IFERR DOPATH RCL THEN DROP ERRN ERRM SWAP DROP END

# Replace # with " " in TFA and store in R
""
1 TFA SIZE FOR I
    TFA I I SUB
    DUP ERRN B→R 481 - CHR == IF THEN DROP " " END
    +
NEXT

# Check that the two string match
≠ IF THEN ABORT END

# Check that ENC is uppercase
1 ENC SIZE FOR I
    ENC I I SUB NUM DUP 65 ≥ SWAP 90 ≤ AND NOT IF THEN ABORT END
NEXT

# Push ENC to stack
ENC

# Apply ROT10 to ENC
'S' STO
"" 'R' STO
S SIZE 1
SWAP
FOR I
S I DUP SUB NUM
3 - 26 MOD
"A" NUM +
CHR
R SWAP + 'R' STO
NEXT
R

# "Bad Argument Type"
IFERR "aigjbospgf" 9683 + THEN DROP DROP ERRM DUP END DROP
# "Argument Type"
5 17 SUB

# Store in D
'D' STO

# Strip spaces and put the result on the stack
"" 1 D SIZE FOR I D I I SUB DUP NUM 32 == IF THEN DROP ELSE + END NEXT

# Perform TOUPPER on R
'SA' STO
  "" 'RA' STO
  1 SA SIZE FOR I
    RA SA I I SUB NUM
    DUP 97 ≥ DUP 122 ≤ AND IF THEN 32 - END
    CHR
    + 'RA' STO
  NEXT
  RA

# Compare the two
≠ IF THEN ABORT END
DROP
DROP
"FLAG CORRECT"
»

'CHKFLG'
STO
```
